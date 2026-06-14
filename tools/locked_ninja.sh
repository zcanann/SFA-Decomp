#!/bin/bash
# Serialize ninja invocations across parallel matching agents to avoid
# .ninja_log corruption / build-dir lock contention. Uses a directory mutex.
# Usage: tools/locked_ninja.sh <ninja args...>
LOCKDIR="/tmp/sfa_ninja.lock"
cd "$(dirname "$0")/.." || exit 1
for i in $(seq 1 600); do
  if mkdir "$LOCKDIR" 2>/dev/null; then
    trap 'rmdir "$LOCKDIR" 2>/dev/null' EXIT
    ninja "$@"
    rc=$?
    rmdir "$LOCKDIR" 2>/dev/null
    trap - EXIT
    exit $rc
  fi
  sleep 0.5
done
echo "locked_ninja: timed out waiting for build lock" >&2
exit 1
