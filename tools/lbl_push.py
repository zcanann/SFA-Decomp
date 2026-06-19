#!/usr/bin/env python3
"""Apply a rename mapping, verify no regression, commit, and push to main with
retry against fast-moving upstream.

Renames are name-only (dtk re-extracts the target from symbols.txt), so on an
upstream conflict we reset to origin/main and re-apply the same mapping
deterministically rather than resolving textual conflicts.

Usage: lbl_push.py mapping.json "commit message"
"""
from __future__ import annotations
import subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sh(cmd, check=True, quiet=False):
    r = subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True)
    if not quiet:
        out = (r.stdout + r.stderr).strip()
        if out:
            print(out[-1500:])
    if check and r.returncode != 0:
        sys.exit(f"FAILED: {cmd}")
    return r


def shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    mapping, msg = sys.argv[1], sys.argv[2]
    sh(f"python3 tools/lbl_rename.py check {mapping}")
    sh(f"python3 tools/lbl_rename.py apply {mapping}")
    r = subprocess.run("python3 tools/lbl_build_verify.py", shell=True, cwd=ROOT,
                       capture_output=True, text=True)
    print((r.stdout + r.stderr)[-1500:])
    if r.returncode != 0:
        sys.exit("verification FAILED — not committing")
    sh(f"git add -A && git commit -q -m {shquote(msg)}")
    for attempt in range(6):
        sh("git fetch origin -q", quiet=True)
        rb = sh("git rebase origin/main", check=False, quiet=True)
        if rb.returncode != 0:
            print(f"[attempt {attempt}] rebase conflict -> reset+reapply")
            sh("git rebase --abort", check=False, quiet=True)
            sh("git reset --hard origin/main", quiet=True)
            sh(f"python3 tools/lbl_rename.py apply {mapping}", quiet=True)
            sh(f"git add -A && git commit -q -m {shquote(msg)}", quiet=True)
        push = sh("git push origin HEAD:main", check=False, quiet=True)
        if push.returncode == 0:
            print(f"PUSHED (attempt {attempt})")
            return
        print(f"[attempt {attempt}] push rejected, retrying")
    sys.exit("push failed after retries")


if __name__ == "__main__":
    main()
