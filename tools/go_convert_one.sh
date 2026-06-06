#!/usr/bin/env bash
# Convert one TU's GameObject derefs and gate the .o byte-for-byte.
# Usage: go_convert_one.sh <src/path/file.c> <basevar> [basevar...] [--bytecast-only]
# Reverts the file if the gate fails or compile breaks.
set -u
ROOT="c:/Projects/SFA-Decomp"
cd "$ROOT" || exit 2
F="$1"; shift
OBJ="build/GSAE01/src/${F#src/}"; OBJ="${OBJ%.c}.o"
BASE="/tmp/baseline_o/$(basename "${F%.c}").o"
mkdir -p /tmp/baseline_o

# 1. ensure current .o built, save baseline
ninja "$OBJ" >/dev/null 2>&1 || { echo "PREBUILD-FAIL $F"; exit 2; }
cp "$OBJ" "$BASE"
cp "$F" "/tmp/$(basename "$F").orig"

# 2. convert
python3 tools/deref_convert_gameobject.py "$F" "$@"

# 3. add include if missing
if ! grep -q 'main/game_object.h' "$F"; then
  # insert after first #include
  awk 'NR==1{print; print "#include \"main/game_object.h\""; next} {print}' "$F" > "$F.tmp" && mv "$F.tmp" "$F"
fi

# 4. gate
if python3 tools/deref_o_gate.py "$BASE" "$OBJ" --rebuild . >/tmp/gate.log 2>&1; then
  echo "PASS $F"
else
  echo "FAIL $F"
  tail -6 /tmp/gate.log
  cp "/tmp/$(basename "$F").orig" "$F"
  ninja "$OBJ" >/dev/null 2>&1
  exit 1
fi
