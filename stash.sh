#!/bin/bash

set -e

OPTIONS="dek:c:D:"
CIPHER=${STASH_CIPHER:-aes-256-cbc}
MODE=decrypt
HMAC=${STASH_HMAC:-sha512}
KEY=$STASH_KEY
TMPDIRCLEAN=true
INFILE=-
OUTFILE=-

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

You may override the defaults using the following variables:
STASH_KEY, STASH_CIPHER, and STASH_HMAC.
EOF
  exit 1
}

while true ; do
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

function error() {
  echo "ERROR: $*" 1>&2
  rm -rf $TMPDIR
  exit 1
}

function stash_nonce() {
  SIZE=$(( $1 + 0 ))
  LENGTH=$(( $1 * 2 ))

  if [[ $SIZE -lt 16 ]]; then
    error "Unable to create nonce shorter than 16 bytes"
  fi

  RET=$(date +"%s %N" | awk '{printf "%08x%08x\n", $1, $2}')

  EXTRA=$(( $LENGTH - ${#RET} ))
  if [[ $EXTRA -gt 0 ]]; then
    RET="$RET$(openssl rand -hex $(( $EXTRA / 2 )))"
  fi
}

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

function stash_cipher_params() {
  local CIPHER
  local KEYSIZE
  local IVSIZE

  case $1 in
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

function check_key_iv() {
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

function openssl_encrypt() {
  local CIPHER=$1
  local KEY=$2
  local IV=$3

  openssl enc -e -$CIPHER -K $KEY -iv $IV
}

function openssl_decrypt() {
  local CIPHER=$1
  local KEY=$2
  local IV=$3

  openssl enc -d -$CIPHER -K $KEY -iv $IV
}

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
    fi
  fi

  stash_nonce $IVSIZE
  IV=$RET

  check_key_iv $CIPHER $KEY $IV

  HMAC_DATA=$(tee < $INFILE >(openssl_encrypt $CIPHER $KEY $IV > $TMPDIR/encrypted) | openssl_hmac $HMAC $KEY)

  echo "Timestamp: $(date -u --iso-8601=seconds)" > $TMPDIR/control
  echo "Cipher: $CIPHER" >> $TMPDIR/control
  echo "IV: $IV" >> $TMPDIR/control
  echo "HMAC: $HMAC_DATA" >> $TMPDIR/control

  cat $TMPDIR/control 1>&2
  echo "Key: $KEY" 1>&2

  echo "control" > $TMPDIR/manifest
  echo "encrypted" >> $TMPDIR/manifest

  (cd $TMPDIR && cat manifest | cpio --quiet -o) > $OUTFILE
}

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
  done < $TMPDIR/control

  check_key_iv $CIPHER $KEY $IV

  HMAC_DATA=$(openssl_decrypt $CIPHER $KEY $IV < $TMPDIR/encrypted | openssl_hmac $HMAC $KEY)
  set -- $HMAC_DATA
  HMAC_OUT=$2

  if [[ $HMAC_OUT != $HMAC_OK ]]; then
    error "HMAC verification failed!  Are you using the right key?"
  fi

  openssl_decrypt $CIPHER $KEY $IV < $TMPDIR/encrypted > $OUTFILE
}

case $MODE in
  encrypt) stash_encrypt ;;
  decrypt) stash_decrypt ;;
esac

if [[ $TMPDIRCLEAN = true ]]; then
  rm -rf $TMPDIR
fi

exit 0
