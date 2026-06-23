#!/bin/bash
# Validate the decompiled Coloring.c Select against the live compiler for one unit.
# Usage: tools/mwcc_re/validate_select.sh <src/.../unit.c>
# Dumps (availMask, chosenReg) at every Select assignment (0x50899e) + fallbacks,
# plus the per-class register tables. Compare the produced .o to the project build
# to confirm it's the real compilation. Requires gdb + build/tools/wibo.
set -e
SRC="$1"
OUT=$(mktemp -d)
FLAGS="-nodefaults -proc gekko -align powerpc -enum int -fp hardware -Cpp_exceptions off
 -O4,p -inline auto -maxerrors 1 -nosyspath -RTTI off -fp_contract on -str reuse -multibyte
 -i include -i build/GSAE01/include -DBUILD_VERSION=0 -DVERSION_GSAE01 -DNDEBUG=1
 -opt nopeephole,noschedule -lang=c"
gdb -batch -x tools/mwcc_re/select_dump.gdb --args \
  build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe $FLAGS \
  -pragma "cats off" -pragma "warn_notinlined off" -c "$SRC" -o "$OUT/"
echo "produced: $OUT/$(basename ${SRC%.c}).o"
