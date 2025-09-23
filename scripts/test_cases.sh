#!/bin/sh
set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT_DIR/http_client"
OUT_DIR="$ROOT_DIR/test_outputs"
REF_DIR="$ROOT_DIR/test_refs"

mkdir -p "$OUT_DIR" "$REF_DIR"

URLS="
https://zechuncao.com/teaching/CSCI4406/test1.txt
https://zechuncao.com/teaching/CSCI4406/test2.png
https://zechuncao.com/teaching/CSCI4406/test3.txt
https://zechuncao.com/teaching/CSCI4406/minigzip
https://zechuncao.com/teaching/CSCI4406/inffast.o
https://zechuncao.com/teaching/CSCI4406/Makefile
https://zechuncao.com/teaching/CSCI4406/25F_CSCI4406_900_Computer_Networks_Syllabus.pdf
"

echo "Fetching references with curl..." >&2
for u in $URLS; do
  name=$(basename "$u")
  curl -fsSL "$u" -o "$REF_DIR/$name"
done

echo "Building http_client..." >&2
make -C "$ROOT_DIR" >/dev/null

echo "Fetching with http_client (HTTP only; HTTPS will fail until teammate adds TLS)." >&2
for u in $URLS; do
  name=$(basename "$u")
  if ! "$BIN" -u "$u" -o "$OUT_DIR/$name"; then
    echo "WARN: fetch failed for $u (expected for https until TLS is added)" >&2
  fi
done

echo "Diffing outputs to references..." >&2
fail=0
for f in "$REF_DIR"/*; do
  base=$(basename "$f")
  if [ -f "$OUT_DIR/$base" ]; then
    if ! cmp -s "$f" "$OUT_DIR/$base"; then
      echo "DIFF: $base differs" >&2
      fail=1
    fi
  else
    echo "MISSING: $base (likely due to https)" >&2
    fail=1
  fi
done

exit $fail


