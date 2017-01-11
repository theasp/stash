#!/bin/bash

set -e

# Defaults
CIPHER=${STASH_CIPHER:-aes-256-cbc}
MODE=decrypt
HMAC=${STASH_HMAC:-sha512}
KEY=$STASH_KEY
KEYGEN=false
TMPDIRCLEAN=true
INFILE=-
OUTFILE=-
VERBOSE=false

function stash_cleanup() {
  if [[ $TMPDIR ]] && [[ $TMPDIRCLEAN = true ]]; then
    rm -rf $TMPDIR
  fi
}

function error() {
  echo "ERROR: $*" 1>&2
  stash_cleanup
  exit 1
}

function warn() {
  echo "WARNING: $*" 1>&2
}

function info() {
  echo "INFO: $*" 1>&2
}

function stash_usage() {
  cat >&2 <<EOF
Usage: `basename $0` [OPTION]
Encrypt or decrypt a file from INFILE (or STDIN) into OUTFILE (or STDOUT).

  -e, --encrypt
      Encrypt INFILE and store in OUTFILE, using a provided or
      generated key.  The key used is written to STDERR.
  -d, --decrypt
      Decrypt INFILE (default), using a provided key.
  -i INFILE, --in INFILE
      The name of the input file, or - for STDIN (default).
  -o OUTFILE, --out OUTFILE
      The name of the output file, or - for STDOUT (default).
  -k KEY, --key KEY
      A key of appropriate length in hex format.
  -c CIPHER, --cipher CIPHER
      Specify a cipher from one of: aes-256-cbc (default),
      aes-192-cbc, or aes-128-cbc.
  -H DIGEST, --hmac DIGEST
      Specify the digest algorithm to use for the HMAC from one of:
      sha512 (default), sha384, sha256, sha224, sha
  -T TMPDIR, --tmpdir TMPDIR
      Use TMPDIR to (de)construct the stash file.
  -v, --verbose
      More output.

You may override the defaults using the following variables:
STASH_KEY, STASH_CIPHER, and STASH_HMAC.
EOF
  exit 1
}

# Parse arguments
function stash_getopts() {
  while true; do
    case "$1" in
      -e|--encrypt)
        MODE=encrypt
        shift
        ;;

      -d|--decrypt)
        MODE=decrypt
        shift
        ;;

      -k|--key)
        KEY=$2
        shift 2
        ;;

      -c|--cipher)
        CIPHER=$2
        shift 2
        ;;

      -H|--hmac)
        HMAC=$2
        shift 2
        ;;

      -i|--in)
        INFILE=$2
        shift 2
        ;;

      -o|--out)
        OUTFILE=$2
        shift 2
        ;;

      -T|--tmpdir)
        TMPDIR=$2
        TMPDIRCLEAN=false
        shift 2
        ;;

      -v|--verbose)
        VERBOSE=true
        shift
        ;;

      --)
        shift
        break
        ;;

      -*)
        echo "ERROR: Unknown option: $1" 1>&2
        stash_usage
        ;;

      *)
        break
        ;;
    esac
  done

  if [[ -z $TMPDIR ]]; then
    TMPDIR=$(mktemp -d /tmp/stash-XXXXXXXXXX)
  fi

  if [[ -z $INFILE ]] || [[ $INFILE = '-' ]]; then
    INFILE=/dev/stdin
  fi

  if [[ -z $OUTFILE ]] || [[ $OUTFILE = '-' ]]; then
    OUTFILE=/dev/stdout
  fi
}


# Generate a nonce of atleast 16 bytes using the system clock, and add
# extra bytes of random to get the desired length.
function stash_nonce() {
  SIZE=$(( $1 + 0 ))
  LENGTH=$(( $1 * 2 )) # * 2 for hex length

  if [[ $SIZE -lt 16 ]]; then
    error "Unable to create nonce shorter than 16 bytes"
  fi

  RET=$(date +"%s %N" | awk '{printf "%08x%08x\n", $1, $2}')

  EXTRA=$(( $LENGTH - ${#RET} ))
  if [[ $EXTRA -gt 0 ]]; then
    RET="$RET$(openssl rand -hex $(( $EXTRA / 2 )))"
  fi
}

# Calculate the HMAC for a given key.
# TODO: Handle wrong sized key?
function openssl_hmac() {
  local DIGEST=$1
  local KEY=$2

  case $DIGEST in
    sha|sha1|sha-1|SHA|SHA1|SHA-1)
      DIGEST=sha1
      ;;

    sha224|sha-224|SHA224|SHA-224)
      DIGEST=sha224
      ;;

    sha256|sha-256|SHA256|SHA-256)
      DIGEST=sha256
      ;;

    sha384|sha-384|SHA384|SHA-384)
      DIGEST=sha384
      ;;

    sha512|sha-512|SHA512|SHA-512)
      DIGEST=sha512
      ;;
    *)
      error "Unknown digest: $DIGEST" ;;
  esac

  set -- $(openssl dgst -r -hmac $KEY -$DIGEST)
  echo "$DIGEST $1"
}

# Get the openssl cipher name, key size and iv size.
function stash_cipher_params() {
  local CIPHER=$1
  local KEYSIZE
  local IVSIZE

  case $CIPHER in
    aes128|aes-128-cbc|AES-128-CBC)
      CIPHER=aes-128-cbc
      KEYSIZE=16
      IVSIZE=16
      ;;

    aes192|aes-192-cbc|AES-192-CBC)
      CIPHER=aes-192-cbc
      KEYSIZE=24
      IVSIZE=16
      ;;

    aes256|aes-256-cbc|AES-256-CBC)
      CIPHER=aes-256-cbc
      KEYSIZE=32
      IVSIZE=16
      ;;

    *)
      error "Unknown cipher: $CIPHER"
  esac

  if [[ -z $IVSIZE ]]; then
    IVSIZE=$KEYSIZE
  fi

  echo "$CIPHER $KEYSIZE $IVSIZE"
}

# Verify the key and IV are the correct sizes.
function stash_verify_keyiv() {
  local CIPHER=$1
  local KEY=$2
  local IV=$3

  set -- $(stash_cipher_params $CIPHER)
  local KEYSIZE=$2
  local IVSIZE=$3

  if [[ $(( ${#KEY} / 2 )) != $KEYSIZE ]]; then
    error "The key is the wrong size: $(( ${#KEY} / 2) )) != $KEYSIZE"
  fi

  if [[ $(( ${#IV} / 2 )) != $IVSIZE ]]; then
    error "The iv is the wrong size: $(( ${#IV} / 2 )) != $IVSIZE"
  fi
}

# Encrypt data
function openssl_encrypt() {
  openssl enc -e -$1 -K $2 -iv $3
}

# Decrypt data
function openssl_decrypt() {
  openssl enc -d -$1 -K $2 -iv $3
}

# Create a container using cpio with the encrypted version of
# INFILE. The minimum size of tar is rather big, and ar can't be used
# with stdin/out.  The container contains the files `meta` and
# `encrypted`. `meta` looks like this:
# Timestamp: 2017-01-11T20:31:37+0000
# Cipher: aes-256-cbc
# IV: 58769629098ad8d4c7da6cd41692543b
# HMAC: sha512 0d3a65b8d1680aca0a80c6f93441a12c1140e3c2a8f3b77ba8a3e392b1466704b742b84c83e519368a27f4a7d10abfe227b73314663dfc202731c5e9db09ff03
function stash_encrypt() {
  set -- $(stash_cipher_params $CIPHER)
  CIPHER=$1
  KEYSIZE=$2
  IVSIZE=$3

  if [[ -z $KEY ]]; then
    if [[ $STASH_KEY ]]; then
      KEY=$STASH_KEY
    else
      KEY=$(openssl rand -hex $KEYSIZE)
      KEYGEN=true
    fi
  fi

  stash_nonce $IVSIZE
  IV=$RET

  stash_verify_keyiv $CIPHER $KEY $IV

  # Use process redirectgion to write the encrypted data to
  # $TMPDIR/encrypted while calculating the HMAC at the same time.
  # This is to prevent unencrypted data from going to disk, unless
  # bash is emulating process redirection on your operating system.
  HMAC_DATA=$(tee < $INFILE >(openssl_encrypt $CIPHER $KEY $IV > $TMPDIR/encrypted) | openssl_hmac $HMAC $KEY)

  echo "Timestamp: $(date -u --iso-8601=seconds)" > $TMPDIR/meta
  echo "Cipher: $CIPHER" >> $TMPDIR/meta
  echo "IV: $IV" >> $TMPDIR/meta
  echo "HMAC: $HMAC_DATA" >> $TMPDIR/meta

  if [[ $VERBOSE = true ]]; then
    info "Meta:"
    cat $TMPDIR/meta | sed -e 's/^/\ci/' 1>&2
  fi

  if [[ $KEYGEN = true ]] || [[ $VERBOSE = true ]]; then
    info "Key: $KEY"
  fi

  echo "meta" > $TMPDIR/manifest
  echo "encrypted" >> $TMPDIR/manifest

  (cd $TMPDIR && cat manifest | cpio --quiet -o) > $OUTFILE

  if [[ $VERBOSE = true ]]; then
    info "Encryption successful"
  fi
}

# Extract the files from the container, decrypt and verify the HMAC.
# If the HMAC matches the value from the container, decrypt again and
# put in $OUTFILE.  TODO: I would like to avoid the double decryption
# without writing to disk.
function stash_decrypt() {
  if [[ -z $KEY ]]; then
    error "Unable to decrypt without providing a key"
  fi

  (cd $TMPDIR && cpio --quiet -i) < $INFILE

  while read line; do
    set -- $line
    case $1 in
      Cipher:)
        CIPHER=$2
        ;;

      HMAC:)
        HMAC=$2
        HMAC_OK=$3
        ;;

      IV:)
        IV=$2
        ;;
    esac
  done < $TMPDIR/meta

  stash_verify_keyiv $CIPHER $KEY $IV

  HMAC_DATA=$(openssl_decrypt $CIPHER $KEY $IV < $TMPDIR/encrypted | openssl_hmac $HMAC $KEY)
  set -- $HMAC_DATA
  HMAC_OUT=$2

  if [[ $HMAC_OUT != $HMAC_OK ]]; then
    error "HMAC verification failed!  Are you using the right key?"
  fi

  openssl_decrypt $CIPHER $KEY $IV < $TMPDIR/encrypted > $OUTFILE

  if [[ $VERBOSE = true ]]; then
    info "Decryption successful"
  fi
}

# Main function
function stash_main() {
  stash_getopts "$@"

  case $MODE in
    encrypt) stash_encrypt ;;
    decrypt) stash_decrypt ;;
  esac

  stash_cleanup

  exit 0
}

stash_main "$@"
