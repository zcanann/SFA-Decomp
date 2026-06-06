#!/usr/bin/env bash
# Convert one TU's per-class state derefs and gate the .o byte-for-byte.
# Usage: go_convert_struct.sh <src/file.c> <header.h> <StructName> <var> [var...]
set -u
ROOT="c:/Projects/SFA-Decomp"; cd "$ROOT" || exit 2
F="$1"; HDR="$2"; SNAME="$3"; shift 3
OBJ="build/GSAE01/src/${F#src/}"; OBJ="${OBJ%.c}.o"
BASE="/tmp/baseline_o/$(basename "${F%.c}").o"
mkdir -p /tmp/baseline_o
ninja "$OBJ" >/dev/null 2>&1 || { echo "PREBUILD-FAIL $F"; exit 2; }
cp "$OBJ" "$BASE"
cp "$F" "/tmp/$(basename "$F").orig"
python3 tools/deref_convert_struct.py "$F" "$HDR" "$SNAME" "$@"
HINC="${HDR#include/}"
if ! grep -q "$HINC" "$F"; then
  awk -v inc="$HINC" 'NR==1{print; print "#include \"" inc "\""; next} {print}' "$F" > "$F.tmp" && mv "$F.tmp" "$F"
fi
if python3 tools/deref_o_gate.py "$BASE" "$OBJ" --rebuild . >/tmp/gate.log 2>&1; then
  echo "PASS $F"
else
  echo "FAIL $F"; tail -4 /tmp/gate.log
  cp "/tmp/$(basename "$F").orig" "$F"; ninja "$OBJ" >/dev/null 2>&1; exit 1
fi
