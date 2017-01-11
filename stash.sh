#!/bin/bash

set -ex

OPTIONS="dek:c:D:"
CIPHER=aes-256-cbc
MODE=encrypt
HMAC=sha512

if ( ! getopts $OPTIONS opt); then
  cat >&2 <<EOF
Usage:
  Encrypt: `basename $0` -e [-k key] [-c cipher] [-H hmac] [in] [out]
  Decrypt: `basename $0` -d -k <key> [in] [out]
EOF
  exit $E_OPTERROR;
fi

while getopts $OPTIONS opt; do
  case $opt in
    e) MODE=encrypt ;;
    d) MODE=decrypt ;;
    c) CIPHER=$OPTARG ;;
    D) DIGEST=$OPTARG ;;
    k) KEY=$OPTARG ;;
  esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift

READ=$1
WRITE=$2

TMPDIR=$(mktemp -d /tmp/stash-XXXXXXXXXX)
if [[ -z $READ ]] || [[ $READ = '-' ]]; then
  READ=/dev/stdin
fi

if [[ -z $WRITE ]] || [[ $WRITE = '-' ]]; then
  WRITE=/dev/stdout
fi

function error() {
  echo "ERROR: $*" 1>&2
  rm -rf $TMPDIR
  exit 1
}

function stash_make_nonce() {
  SIZE=${1:-16}
  RANDOM=$(( $SIZE - 16 ))
  if [[ $RANDOM -gt 0 ]]; then
    #RANDOM=$(openssl rand -hex $RANDOM)
    true
  else
    RANDOM=""
  fi
  RET=$(date +"%s %N $RANDOM" | awk '{printf "%08x%08x%s\n", $1, $2, $3}' | cut -c 1-$SIZE)
}

function stash_hmac() {
  local DIGEST=$1
  local KEY=$2
  local FILE=$3
  local CMD

  case $DIGEST in
    sha|sha1|sha-1|SHA|SHA1|SHA-1)
      CMD="-sha1"
      DIGEST=sha1
      ;;

    sha224|sha-224|SHA224|SHA-224)
      CMD="-sha224"
      DIGEST=sha224
      ;;

    sha256|sha-256|SHA256|SHA-256)
      CMD="-sha256"
      DIGEST=sha256
      ;;

    sha384|sha-384|SHA384|SHA-384)
      CMD="-sha384"
      DIGEST=sha384
      ;;

    sha512|sha-512|SHA512|SHA-512)
      CMD="-sha512"
      DIGEST=sha512
      ;;
    *)
      error "Unknown digest: $DIGEST" ;;
  esac

  set -- $(openssl dgst -r -hmac $KEY $CMD < $FILE)
  RET="$DIGEST $1"
}

function stash_cipher_params() {
  case $1 in
    aes128|aes-128-cbc|AES-128-CBC)
      RET="aes-128-cbc 8"
      ;;

    aes192|aes-192-cbc|AES-192-CBC)
      RET="aes-192-cbc 24"
      ;;

    aes256|aes-256-cbc|AES-256-CBC)
      RET="aes-256-cbc 16"
      ;;

    *)
      error "Unknown cipher: $CIPHER"
  esac
}

function stash_encrypt() {
  stash_cipher_params $CIPHER
  set -- $RET
  CIPHER=$1
  BSIZE=$2

  if [[ -z $KEY ]]; then
    if [[ $STASH_KEY ]]; then
      KEY=$STASH_KEY
    else
      KEY=$(openssl rand -hex $BSIZE)
    fi
  fi

  if [[ ${#KEY} -ne $(( $BSIZE * 2 )) ]]; then
    error "Supplied key is not the correct length: ${#KEY} != $BSIZE"
  fi

  stash_make_nonce
  IV=$RET

  cat $READ > $TMPDIR/unencrypted

  stash_hmac $HMAC $KEY $TMPDIR/unencrypted
  HMAC_DATA=$RET
  
  openssl enc -e -$CIPHER -K $KEY -iv $IV -in $TMPDIR/unencrypted -out $TMPDIR/encrypted || error "Unable to encrypt data"
  rm -f $TMPDIR/unencrypted

  cat > $TMPDIR/control <<EOF
Cipher: $CIPHER
IV: $IV
HMAC: $HMAC_DATA
EOF
  
  echo "Key: $KEY" 1>&2
  cat $TMPDIR/control 1>&2

  cat > $TMPDIR/manifest <<EOF
control
encrypted
EOF
  
  #tar -C $TMPDIR -c control encrypted | base64
  (cd $TMPDIR && cat manifest | cpio -o > $WRITE)
}

function stash_decrypt() {
  if [[ -z $KEY ]]; then
    error "Unable to decrypt without supplying a key"
  fi
  
  (cd $TMPDIR && cpio -i) < $READ
  set -- $(grep "^Cipher:" < $TMPDIR/control)
  CIPHER=$2

  set -- $(grep "^HMAC:" < $TMPDIR/control)
  HMAC=$2

  set -- $(grep "^IV:" < $TMPDIR/control)
  IV=$2

  stash_cipher_params $CIPHER
  set -- $RET
  CIPHER=$1
  BSIZE=$2

  openssl enc -d -$CIPHER -K $KEY -iv $IV -in $TMPDIR/encrypted -out $TMPDIR/unencrypted || error "Unable to encrypt data"
  rm -rf $TMPDIR/encrypted

  stash_hmac $HMAC $KEY $TMPDIR/unencrypted
  set -- $RET
  ACTUAL_HMAC=$2

  cat $TMPDIR/unencrypted > $WRITE
  
  ls -l $TMPDIR
}

case $MODE in
  encrypt) stash_encrypt ;;
  decrypt) stash_decrypt ;;
esac

rm -rf $TMPDIR

exit 0

