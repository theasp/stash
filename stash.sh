#!/bin/bash

set -x

OPTIONS="dek:c:D:"
CIPHER=aes-256-gcm
MODE=encrypt
DIGEST=sha512

if ( ! getopts $OPTIONS opt); then
  cat >&2 <<EOF
Usage:
  Encrypt: `basename $0` -e [-k key] [-c cipher] [-D digest] [in] [out]
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

function stash_make_nonce() {
  SIZE=${1:-16}
  RET=$(date +"%s %N" | awk '{printf "%08x%08x\n", $1, $2}' | cut -c 1-$SIZE)
}

function stash_digest() {
  local DIGEST=$1
  local FILE=$2

  case $DIGEST in
    sha|sha1|sha-1|SHA|SHA1|SHA-1)
      RET=$(sha1sum $FILE | cut -f 1 -d ' ') ;;
    
    sha224|sha-224|SHA224|SHA-224)
      RET=$(sha224sum $FILE | cut -f 1 -d ' ') ;;
    
    sha256|sha-256|SHA256|SHA-256)
      RET=$(sha256sum $FILE | cut -f 1 -d ' ') ;;

    sha384|sha-384|SHA384|SHA-384)
      RET=$(sha384sum $FILE | cut -f 1 -d ' ') ;;

    sha512|sha-512|SHA512|SHA-512)
      RET=$(sha512sum $FILE | cut -f 1 -d ' ') ;;

    md5|MD5)
      RET=$(md5sum $FILE | cut -f 1 -d ' ') ;;
  esac
}

function stash_encrypt() {
  echo "Read: $READ  Write: $WRITE"
  
  if [[ -z $KEY ]]; then
    KEY=$(openssl rand -hex 16)
  fi

  stash_make_nonce
  IV=$RET

  cat $READ > $TMPDIR/unencrypted

  stash_digest $DIGEST $TMPDIR/unencrypted
  DIGEST_DATA=$RET

  openssl $CIPHER -e -K $KEY -iv $IV < $TMPDIR/unencrypted > $TMPDIR/encrypted
  rm -f $TMPDIR/unencrypted
  
  cat > $TMPDIR/control <<EOF
IV: $IV
Cipher: $CIPHER
Digest: $DIGEST $DIGEST_DATA
EOF

  echo "Key: $KEY" 1>&2
  cat $TMPDIR/control 1>&2
  
  ar r $TMPDIR/stash $TMPDIR/control $TMPDIR/encrypted
  cat $TMPDIR/stash > $WRITE
}

function stash_decrypt() {
  false
}

case $MODE in
  encrypt) stash_encrypt ;;
  decrypt) stash_decrypt ;;
esac

rm -rf $TMPDIR

exit 0

