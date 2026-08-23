"""Score alternative C spellings of one or more source sites against report.json.

Rewrites a source file in place for each candidate variant, rebuilds just that
unit, regenerates report.json and prints the unit and per-function
fuzzy_match_percent plus the object sha1. The original file is always restored.

Two properties matter more than they look:

- It gates on report.json, never on a diff tool. A byte-closer spelling can
  score lower, so only the report decides.
- It prints the object sha1 next to every score. An identical sha means the
  spelling was inert -- MWCC folded it back to the same code -- which is the
  difference between "this lever does not apply here" and "this lever lost".
  Several apparent results have turned out to be one build reported twice.

It also survives a shared worktree. Sibling lanes delete objects out from under
a running build, which makes `ninja` exit 0 while report.json fails to open a
missing .o, and makes an unrelated probe read as BUILDFAIL. Each build retries,
rebuilding whatever a sibling removed, and abandons the measurement outright if
our own object was clobbered rather than reporting a foreign build as ours.

Usage:
    python3 tools/probe_spelling.py <src> <obj> <unit> <fn> <old> <new1> [new2...]

    src   source file to rewrite, repo-relative
    obj   object to rebuild, e.g. build/GSAE01/src/main/newshadows.o
    unit  report.json unit name, e.g. main/main/newshadows
    fn    function to report; comma-separate for several
    old   exact text to replace (every occurrence)
    newN  candidate replacements, measured in order

For multi-site variants needing several simultaneous substitutions, import
run() and pass [(label, [(old, new), ...]), ...].
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = "build/GSAE01/report.json"
MAX_RETRIES = 8


def score(unit_name, fns):
    with open(os.path.join(ROOT, REPORT)) as handle:
        data = json.load(handle)
    for unit in data["units"]:
        if unit["name"] == unit_name:
            per_fn = {
                # objdiff omits the key at 0.0; absent means zero, not absent
                f["name"]: round(float(f.get("fuzzy_match_percent") or 0.0), 4)
                for f in (unit.get("functions") or [])
                if f["name"] in fns
            }
            return float(unit["measures"].get("fuzzy_match_percent") or 0.0), per_fn
    return None, None


def build(obj):
    """Build obj and report.json. Returns the object sha1, or None when the
    measurement cannot be trusted."""
    path = os.path.join(ROOT, obj)
    if os.path.exists(path):
        os.remove(path)
    result = subprocess.run(["ninja", obj], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0 or not os.path.exists(path):
        sys.stderr.write(result.stdout[-2000:])
        return None
    sha = hashlib.sha1(open(path, "rb").read()).hexdigest()[:10]
    for _ in range(MAX_RETRIES):
        subprocess.run(["ninja"], cwd=ROOT, capture_output=True, text=True)
        if not os.path.exists(path):
            continue
        if hashlib.sha1(open(path, "rb").read()).hexdigest()[:10] != sha:
            return None
        report = subprocess.run(
            ["ninja", REPORT], cwd=ROOT, capture_output=True, text=True
        )
        if report.returncode == 0:
            return sha
    return None


def run(src, obj, unit_name, fns, variants):
    path = os.path.join(ROOT, src)
    original = open(path, "rb").read()
    text = original.decode("utf-8")
    try:
        sha = build(obj)
        unit, per_fn = score(unit_name, fns)
        print(f"BASE unit={unit} {per_fn} sha={sha}", flush=True)
        last_written = original
        for label, pairs in variants:
            candidate = text
            missing = False
            for old, new in pairs:
                if candidate.count(old) == 0:
                    print(f"  MISS {label}: text not found", flush=True)
                    missing = True
                    break
                candidate = candidate.replace(old, new)
            if missing:
                continue
            candidate_bytes = candidate.encode("utf-8")
            open(path, "wb").write(candidate_bytes)
            last_written = candidate_bytes
            sha = build(obj)
            if sha is None:
                print(f"  BUILDFAIL {label}", flush=True)
                continue
            unit, per_fn = score(unit_name, fns)
            print(f"unit={unit} {per_fn} sha={sha}  <= {label}", flush=True)
    finally:
        # Restore only if the file still holds what this probe last wrote. In the
        # shared worktree a sibling lane can commit into the same file mid-probe;
        # writing back the start-of-probe snapshot silently reverted such a commit
        # once already. If the bytes are unrecognized, leave them alone and say so.
        on_disk = open(path, "rb").read()
        if on_disk in (last_written, original):
            open(path, "wb").write(original)
            build(obj)
        else:
            print(f"NOT RESTORING {path}: changed by another writer mid-probe.",
                  flush=True)
            print("  Your probe edits are NOT in it; reconcile by hand.", flush=True)


def main():
    if len(sys.argv) < 7:
        sys.exit(__doc__)
    src, obj, unit_name, fn, old = sys.argv[1:6]
    fns = fn.split(",")
    variants = [(new, [(old, new)]) for new in sys.argv[6:]]
    sites = open(os.path.join(ROOT, src), "rb").read().decode("utf-8").count(old)
    print(f"sites={sites}")
    if sites == 0:
        sys.exit("old text not found")
    run(src, obj, unit_name, fns, variants)


if __name__ == "__main__":
    main()
