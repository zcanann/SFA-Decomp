#!/bin/bash
# $1 = .c file, $2 = scratch dir
f="$1"
d="$2"
b=$(echo "$f" | tr '/' '_')
pp="$d/$b.i"
clang -target powerpc-unknown-eabi -std=gnu89 -fdeclspec -fms-extensions -E \
  -I. -Iinclude -Ibuild/GSAE01/include \
  -DBUILD_VERSION=0 -DVERSION_GSAE01 -DNDEBUG=1 \
  "$f" -o "$pp" 2>"$d/$b.pperr"
if [ $? -ne 0 ]; then echo "PPFAIL $f"; exit 0; fi
perl -pi -e 's/\s*:\s*\(\s*0[xX][0-9A-Fa-f]+\s*\)\s*;/;/g' "$pp"
out=$(clang -target powerpc-unknown-eabi -std=gnu89 -fdeclspec -fms-extensions \
  -fsyntax-only -Wno-everything \
  -Wuninitialized -Wsometimes-uninitialized -Wconditional-uninitialized -Wreturn-type \
  -x c "$pp" 2>&1)
rc=$?
if echo "$out" | grep -q "error:"; then
  echo "CCFAIL $f"
  echo "$out" | grep "error:" | head -3 | sed "s|^|    |"
fi
echo "$out" | grep -E "warning:" | sed "s|^|$f\t|"
exit 0
