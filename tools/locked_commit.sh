#!/bin/bash
# Atomic `git add <files> && git commit` under a cross-agent mutex, so parallel
# matching agents sharing one working tree don't race on .git/index.lock or
# accidentally sweep each other's staged changes into a commit.
# Usage: tools/locked_commit.sh "commit message" file1 [file2 ...]
LOCKDIR="/tmp/sfa_git.lock"
cd "$(dirname "$0")/.." || exit 1
MSG="$1"; shift
if [ -z "$MSG" ] || [ "$#" -eq 0 ]; then
  echo "usage: locked_commit.sh \"message\" file1 [file2 ...]" >&2
  exit 2
fi
for i in $(seq 1 240); do
  if mkdir "$LOCKDIR" 2>/dev/null; then
    trap 'rmdir "$LOCKDIR" 2>/dev/null' EXIT
    git add -- "$@" && git commit -q -m "$MSG"
    rc=$?
    rmdir "$LOCKDIR" 2>/dev/null; trap - EXIT
    exit $rc
  fi
  sleep 0.5
done
echo "locked_commit: timed out waiting for git lock" >&2
exit 1
