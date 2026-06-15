#!/bin/zsh
# Robust single-object rebuild + report refresh that tolerates concurrent
# agents sharing ninja's build-dir lock. Usage:
#   tools/build_obj.sh <object-path-relative-to-repo>
# Example: tools/build_obj.sh build/GSAE01/src/main/audio/sfx.o
set -u
obj="$1"
cd "${0:A:h}/.."

retry_ninja() {
  local target="$1" i out
  for i in {1..40}; do
    out=$(ninja "$target" 2>&1)
    if print -r -- "$out" | grep -qi "already in use\|ninja: error: build directory"; then
      sleep $((RANDOM % 3 + 2)); continue
    fi
    if print -r -- "$out" | grep -qiE "FAILED|error:"; then
      print -r -- "$out" | grep -iE "FAILED|error:" | head -5
      return 1
    fi
    return 0
  done
  echo "GAVE_UP_LOCK"; return 1
}

rm -f "$obj"
retry_ninja "$obj" || { echo "BUILD_FAILED"; exit 1; }
retry_ninja build/GSAE01/report.json || true
echo "OK_BUILT $obj"
