#!/bin/bash
# Orchestrator-only: rebase local commits onto origin/main and push, with retry.
# Requires a clean working tree (run only between waves, never mid-wave).
cd "$(dirname "$0")/.." || exit 1
rm -f .git/gc.log
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "sync_push: working tree dirty — refusing (run between waves only)" >&2
  exit 2
fi
for i in 1 2 3 4 5; do
  git fetch origin -q 2>/dev/null
  if git rebase origin/main >/tmp/sfa_rebase.log 2>&1; then
    if git push origin main 2>/tmp/sfa_push.log; then
      echo "sync_push: pushed (attempt $i)"
      exit 0
    fi
    echo "sync_push: push rejected, retrying ($i)"
    sleep 2
  else
    echo "sync_push: rebase conflict — aborting, manual fix needed" >&2
    git rebase --abort 2>/dev/null
    cat /tmp/sfa_rebase.log >&2
    exit 1
  fi
done
echo "sync_push: exhausted retries" >&2
exit 1
