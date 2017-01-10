#!/bin/bash

OPTIONS="dek:c:s:d:"
CIPHER=aes-256-gcm
MODE=encrypt
READ=-
WRITE=-
DIGEST=sha512

if ( ! getopts $OPTIONS opt); then
  cat >&2 <<EOF
Usage:
  Encrypt: `basename $0` -e [-k key] [-c cipher] [-s key-size] [-D digest] [in] [out]
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

echo "MODE: $MODE"
echo "Args: $@"
exit 0

set -xe

function stash_make_nonce() {
  SIZE=${1:-16}
  RET=$(date +"%s %N" | awk '{printf "%08x%08x\n", $1, $2}' | cut -c 1-%SIZE)
}

CIPHER=aes-256-gcm
SIZE=256
SIZEB=$(( $SIZE / 8 / 2 ))
KEY=$(openssl rand -hex $SIZEB)
IV=

TMPDIR=$(mktemp -d /tmp/stash-XXXXXXXXXX)


cat > $TMPDIR/control <<EOF
IV: $IV
Cipher: $CIPHER
Digest: $DIGEST $DIGEST_DATA
EOF

openssl $CIPHER -e -K $KEY -iv $IV > $TMPDIR/data

ar r $TMPDIR/stash $TMPDIR/control $TMPDIR/data

echo "Key: $KEY" 1>&2
cat $TMPDIR/control 1>&2

rm -rf $TMPDIR

