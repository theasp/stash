A simple symmetric encryption tool using only openssl.

```
Usage: stash.sh [OPTION]
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
```
