"""Rewrite a file's scheduling/peephole pragmas as the MINIMAL straight-line
transition set that produces the same per-function effective state, then
byte-verify the unit .o (revert on any change).

Per the pragma-provenance findings (CLAUDE.md "Pragma states" section), the
per-fn states are the ground truth we must preserve; the stack-shaped
on/off/reset forests are an artifact of incremental matching. This tool
computes each function's effective state under the existing pragma stack
(on top of the unit's -opt flags default), deletes every sched/peep pragma
line, and re-emits one `#pragma X on|off` immediately before each function
where the state CHANGES (relative to the unit default for the first fn).

Files containing `#pragma push`/`pop` are skipped in auto mode (push/pop
saves pragma state and would interact with synthesized lines) — handle
those manually.

Usage:
  python3 tools/pragma_minimize.py [--apply] [--filter SUBSTR]
With no --apply: dry-run report (per file: current lines -> minimal lines).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pragma_audit import map_fn_states

REPO = Path(__file__).resolve().parent.parent
PRAGMA_LINE = re.compile(rb"^\s*#pragma\s+(scheduling|peephole)\s+(on|off|reset)\s*$")


def unit_default(ninja_text: str, obj_path: str) -> tuple[str, str] | None:
    i = ninja_text.find(f"build {obj_path}:")
    if i < 0:
        return None
    j = ninja_text.find("\nbuild ", i + 1)
    block = ninja_text[i:j]
    return ("off" if "noschedule" in block else "on",
            "off" if "nopeephole" in block else "on")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--filter", default="")
    args = ap.parse_args()

    ninja_text = (REPO / "build.ninja").read_text(encoding="utf-8", errors="replace")
    config = json.loads((REPO / "build" / "GSAE01" / "config.json").read_text())

    total_before = total_after = 0
    changed_files = skipped = reverted = 0
    for u in config["units"]:
        name = u["name"].replace("\\", "/")
        if args.filter and args.filter not in name:
            continue
        src = REPO / "src" / name
        if not src.is_file():
            continue
        data = src.read_bytes()
        pragma_lines = [l for l in data.split(b"\n") if PRAGMA_LINE.match(l)]
        if not pragma_lines:
            continue
        if b"#pragma push" in data or b"#pragma pop" in data:
            print(f"SKIP (push/pop): {name} [{len(pragma_lines)} lines]")
            skipped += 1
            continue
        obj = u["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")
        default = unit_default(ninja_text, obj)
        if default is None or not (REPO / obj).is_file():
            skipped += 1
            continue

        fnmap = map_fn_states(src)
        if not fnmap:
            skipped += 1
            continue
        seq = sorted(((line, s, p) for (line, s, p) in fnmap.values()))
        # synthesize transitions
        inserts: dict[int, list[bytes]] = {}
        cur = default
        for line, s, p in seq:
            eff = (default[0] if s == "def-on" else s,
                   default[1] if p == "def-on" else p)
            pre = []
            if eff[0] != cur[0]:
                pre.append(b"#pragma scheduling " + eff[0].encode())
            if eff[1] != cur[1]:
                pre.append(b"#pragma peephole " + eff[1].encode())
            if pre:
                inserts[line] = pre
            cur = eff
        n_after = sum(len(v) for v in inserts.values())
        total_before += len(pragma_lines)
        total_after += n_after
        print(f"{name}: {len(pragma_lines)} -> {n_after}")
        if not args.apply:
            continue

        lines = data.split(b"\n")
        out = []
        for idx, l in enumerate(lines, 1):
            if PRAGMA_LINE.match(l):
                continue
            if idx in inserts:
                out.extend(inserts[idx])
            out.append(l)
        before_md5 = hashlib.md5((REPO / obj).read_bytes()).hexdigest()
        src.write_bytes(b"\n".join(out))
        r = subprocess.run(["ninja", obj], cwd=REPO, capture_output=True)
        ok = (b"FAILED" not in r.stdout + r.stderr) and \
            hashlib.md5((REPO / obj).read_bytes()).hexdigest() == before_md5
        if ok:
            changed_files += 1
        else:
            src.write_bytes(data)
            subprocess.run(["ninja", obj], cwd=REPO, capture_output=True)
            if hashlib.md5((REPO / obj).read_bytes()).hexdigest() != before_md5:
                raise SystemExit(f"RESTORE FAILED: {name}")
            print(f"  REVERTED (state model wrong for {name})")
            reverted += 1

    print(f"\nlines {total_before} -> {total_after}; "
          f"applied {changed_files}, reverted {reverted}, skipped {skipped}")


if __name__ == "__main__":
    main()
