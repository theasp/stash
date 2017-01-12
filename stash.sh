#!/bin/bash

set -e

# Defaults
CIPHER=${STASH_CIPHER}
MODE=decrypt
DIGEST=${STASH_DIGEST}
KEY=$STASH_KEY
KEYGEN=false
TMPDIRCLEAN=true
INFILE=-
OUTFILE=-
LOGLEVEL=2

function stash_cleanup() {
  if [[ $TMPDIR ]] && [[ $TMPDIRCLEAN = true ]]; then
    rm -rf $TMPDIR
  fi
}

function log-s () {
  local TAG=$1
  local L

  case $TAG in
    debug) L=3 TAG="DEBUG" ;;
    info)  L=2 TAG="INFO" ;;
    warn)  L=1 TAG="WARNING" ;;
    *)     L=0 TAG="ERROR";;
  esac

  if [[ $L -le $LOGLEVEL ]]; then
    sed -e "s/^/$TAG: /" 1>&2
  else
    cat > /dev/null
  fi
}

function log() {
  local LEVEL=$1
  shift
  echo "$@" | log-s $LEVEL
}

function error() {
  log error "$@"
  stash_cleanup
  exit 1
}

function stash_usage() {
  cat <<EOF
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
      A key in hex format, or the absolute path to a file containing a
      key.
  -c CIPHER, --cipher CIPHER
      Specify a cipher from one of: aes-256-cbc (default),
      aes-192-cbc, or aes-128-cbc.
  -D DIGEST, --digest DIGEST
      Specify the digest algorithm to use for the HMAC from one of:
      sha512 (default), sha384, sha256, sha224, sha
  -T TMPDIR, --tmpdir TMPDIR
      Use TMPDIR to (de)construct the stash file.
  -v, -d, --verbose, --debug
      More output. IMPORTANT: When encrypting, this includes
      information that should be kept secret.
  -h, --help
      This help message.

You may override the defaults using the following variables:
STASH_KEY, STASH_CIPHER, and STASH_DIGEST.  The value for the key must
be kept secret.  It is far safer to use the STASH_KEY variable rather
than passing the key on the command line.  Also keep in mind that any
command you type into a shell will likely be recorded in it's history
file.
EOF
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

      -h|--help)
        stash_usage
        exit 0
        ;;

      -D|--digest)
        DIGEST=$2
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
        LOGLEVEL=3
        shift
        ;;

      --)
        shift
        break
        ;;

      -*)
        echo "ERROR: Unknown option: $1" 1>&2
        stash_usage 1>&2
        exit 1
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

  if [[ ${KEY} =~ ^/ ]]; then
    KEY=$(cat $KEY)
  fi
}


# Generate a nonce of atleast 16 bytes using the system clock, and add
# extra bytes of random to get the desired length.
function stash_nonce() {
  SIZE=$(( $1 + 0 ))
  LENGTH=$(( $SIZE * 2 )) # * 2 for hex length

  if [[ $SIZE -lt 16 ]]; then
    error "Unable to create nonce shorter than 16 bytes"
  else
    RET=$(date +"%s %N" | awk '{printf "%08x%08x\n", $1, $2}')

    EXTRA=$(( $LENGTH - ${#RET} ))
    if [[ $EXTRA -gt 0 ]]; then
      EXTRA=$(( $EXTRA / 2 ))
      RET="$RET$(openssl rand -hex $EXTRA)"
    fi
  fi
}

# Calculate the HMAC for a given key.
function openssl_hmac() {
  local DIGEST=$(echo $1 | tr '[:upper:]' '[:lower:]')
  local KEY=$2

  case $DIGEST in
    sha|sha1|sha-1)    DIGEST=sha1 ;;
    sha224|sha-224)    DIGEST=sha224 ;;
    sha256|sha-256)    DIGEST=sha256 ;;
    sha384|sha-384)    DIGEST=sha384 ;;
    sha512|sha-512|"") DIGEST=sha512 ;;

    *)
      error "Unknown digest: $DIGEST" ;;
  esac

  set -- $(openssl dgst -r -hmac $KEY -$DIGEST)
  echo "$DIGEST $1"
}

function stash_cipher_alias() {
  local CIPHER=$1

  CIPHER=$(echo $CIPHER | tr '[:upper:]' '[:lower:]')

  case $CIPHER in
    aes128) CIPHER=aes-128-cbc ;;
    aes192) CIPHER=aes-192-cbc ;;
    aes256) CIPHER=aes-256-cbc ;;
    "")     CIPHER=${STASH_CIPHER:-aes-256-cbc} ;;
  esac

  echo "$CIPHER"
}

function stash_cipher_keysize() {
  local CIPHER=$1

  case $CIPHER in
    *-128-*|*128) KEYSIZE=16 ;;
    *-192-*|*192) KEYSIZE=24 ;;
    *-256-*|*256) KEYSIZE=32 ;;
    *)
      error "Unable to determine key size for cipher: $CIPHER"
      ;;
  esac

  echo "$KEYSIZE"
}

function stash_cipher_blockmode() {
  local CIPHER=$1
  local NEED_HMAC=true

  case $CIPHER in
    *-cbc|*-ctr|*-ofb)
      IVSIZE=16 NEED_HMAC=true ;;
    *-gcm|*-ocb)
      # Previous versions of openssl supported these but didn't check
      # the authentication data.  Current versions don't allow their
      # use.
      error "Unable to use the block mode specified due to limitations of the openssl enc command: $CIPHER"
      ;;
    *)
      error "Unable to determine supported block mode: $CIPHER"
      ;;
  esac

  echo "$IVSIZE $NEED_HMAC"
}


# Get the openssl cipher name, key size and iv size.
function stash_cipher_params() {
  local CIPHER=$1
  local KEYSIZE
  local IVSIZE

  CIPHER=$(stash_cipher_alias $CIPHER)
  KEYSIZE=$(stash_cipher_keysize $CIPHER)

  set -- $(stash_cipher_blockmode $CIPHER)
  IVSIZE=$1
  HMAC=$2

  echo "$CIPHER $KEYSIZE $IVSIZE $HMAC"
}

# Verify the key and IV are the correct sizes.
function stash_verify_keyiv() {
  local CIPHER=$1
  local KEY=$2
  local IV=$3

  set -- $(stash_cipher_params $CIPHER)
  local KEYSIZE=$2
  local IVSIZE=$3

  local ACTUAL_KEYSIZE=$(( ${#KEY} / 2 ))
  local ACTUAL_IVSIZE=$(( ${#IV} / 2 ))

  if [[ $ACTUAL_KEYSIZE != $KEYSIZE ]]; then
    error "The key is the wrong length: $ACTUAL_KEYSIZE != $KEYSIZE"
  fi

  if [[ $ACTUAL_IVSIZE != $IVSIZE ]]; then
    error "The iv is the wrong size: $ACTUAL_IVSIZE != $IVSIZE"
  fi
}

# Encrypt data
function openssl_encrypt() {
  local CIPHER=$1
  local KEY=$2
  local IV=$3
  stash_verify_keyiv $CIPHER $KEY $IV

  openssl enc -e -$CIPHER -K $KEY -iv $IV
}

# Decrypt data
function openssl_decrypt() {
  local CIPHER=$1
  local KEY=$2
  local IV=$3
  stash_verify_keyiv $CIPHER $KEY $IV

  openssl enc -d -$CIPHER -K $KEY -iv $IV
}

# Create a container using cpio with the encrypted version of
# INFILE. The minimum size of tar is rather big, and ar can't be used
# with stdin/out
function stash_encrypt() {
  set -- $(stash_cipher_params $CIPHER)
  local CIPHER=$1
  local KEYSIZE=$2
  local IVSIZE=$3
  local NEED_HMAC=$4

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

  openssl_encrypt $CIPHER $KEY $IV < $INFILE > $TMPDIR/encrypted
  if [[ $NEED_HMAC = true ]]; then
    HMAC=$(cat $TMPDIR/encrypted <(echo $IV) | openssl_hmac "$DIGEST" "$KEY")
  else
    HMAC=""
  fi

  echo "Cipher: $CIPHER" >> $TMPDIR/meta
  echo "IV: $IV" >> $TMPDIR/meta

  if [[ $HMAC ]]; then
    echo "HMAC: $HMAC" >> $TMPDIR/meta
  fi

  log-s debug < $TMPDIR/meta 1>&2

  if [[ $KEYGEN = true ]]; then
    log info "Key: $KEY"
  fi

  (cd $TMPDIR && ls -1 | cpio --quiet -o) > $OUTFILE

  log debug "Encryption successful, to decrypt: $0 -d -i $OUTFILE -o $INFILE"
}

# Extract the files from the container, decrypt and verify the HMAC if provided.
function stash_decrypt() {
  if [[ -z $KEY ]]; then
    read -p 'Key: ' KEY
    if [[ -z $KEY ]]; then
      error "Unable to decrypt without providing a key"
    fi
  fi

  (cd $TMPDIR && cpio --quiet -i) < $INFILE

  while read line; do
    set -- $line
    case $1 in
      Cipher:)
        CIPHER=$2
        ;;

      HMAC:)
        DIGEST=$2
        HMAC_OK=$3
        ;;

      IV:)
        IV=$2
        ;;
    esac
  done < $TMPDIR/meta

  set -- $(stash_cipher_params $CIPHER)
  CIPHER=$1
  KEYSIZE=$2
  IVSIZE=$3
  NEED_HMAC=$4

  stash_verify_keyiv $CIPHER $KEY $IV

  if [[ $NEED_HMAC = true ]]; then
    if [[ -z $HMAC_OK ]]; then
      error "Block mode is not secure and HMAC is missing from control file"
    fi
  fi

  if [[ $HMAC_OK ]]; then
    HMAC=$(cat $TMPDIR/encrypted <(echo $IV) | openssl_hmac "$DIGEST" "$KEY")
    set -- $HMAC
    HMAC_OUT=$2

    if [[ $HMAC_OUT != $HMAC_OK ]]; then
      error "HMAC verification failed!  Are you using the right key?"
    fi
  fi

  openssl_decrypt $CIPHER $KEY $IV < $TMPDIR/encrypted > $OUTFILE

  log info "Decryption successful"
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
