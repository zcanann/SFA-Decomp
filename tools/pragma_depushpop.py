"""Eliminate #pragma push/pop scaffolding: model the FULL pragma environment
(push/pop + per-kind on/off/reset/value stacks), compute each function's
effective state, then rewrite the file with straight-line minimal pragmas.
Byte-gated per unit .o with auto-revert.

Kinds handled: scheduling, peephole, fp_contract, dont_inline,
opt_strength_reduction, opt_loop_invariants, opt_common_subs,
optimization_level (value), ppc_unroll_speculative. Empty push/pop blocks
(state restored before any fn) vanish entirely.

Usage: python3 tools/pragma_depushpop.py [--apply] [--filter SUBSTR]
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

KINDS = ("scheduling", "peephole", "fp_contract", "dont_inline",
         "opt_strength_reduction", "opt_loop_invariants", "opt_common_subs",
         "optimization_level", "ppc_unroll_speculative")
PRAGMA_RE = re.compile(
    rb"^\s*#pragma\s+(push|pop|(" + "|".join(KINDS).encode() +
    rb")\s+(\S+))\s*$")
FNDEF_RE = re.compile(rb"^[A-Za-z_][\w \t\*]*\(")


def kind_defaults(ninja_text: str, obj_path: str) -> dict:
    i = ninja_text.find(f"build {obj_path}:")
    j = ninja_text.find("\nbuild ", i + 1)
    block = ninja_text[i:j] if i >= 0 else ""
    return {
        "scheduling": "off" if "noschedule" in block else "on",
        "peephole": "off" if "nopeephole" in block else "on",
        "fp_contract": "on" if "fp_contract \\$\n      on" or "fp_contract on" in block.replace("$\n      ", "") else "on",
        "dont_inline": "off",
        "opt_strength_reduction": "on",
        "opt_loop_invariants": "on",
        "opt_common_subs": "on",
        "optimization_level": None,
        "ppc_unroll_speculative": "on",
    }


def fn_positions(lines: list[bytes]) -> list[int]:
    """1-based line numbers of function DEFINITIONS (brace before semicolon)."""
    out = []
    for idx, line in enumerate(lines):
        if not line or line[0:1] in (b" ", b"\t", b"#", b"/", b"}"):
            continue
        if b"(" not in line or b"=" in line:
            continue
        if line.startswith((b"extern", b"typedef")):
            continue
        if not FNDEF_RE.match(line):
            continue
        probe, budget, is_def = idx, 8, False
        while budget and probe < len(lines):
            seg = lines[probe].split(b"//")[0]
            if b"{" in seg:
                is_def = True
                break
            if b";" in seg:
                break
            probe += 1
            budget -= 1
        if is_def:
            out.append(idx + 1)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--filter", default="")
    args = ap.parse_args()

    ninja_text = (REPO / "build.ninja").read_text(encoding="utf-8", errors="replace")
    config = json.loads((REPO / "build" / "GSAE01" / "config.json").read_text())

    applied = reverted = 0
    for u in config["units"]:
        name = u["name"].replace("\\", "/")
        if args.filter and args.filter not in name:
            continue
        src = REPO / "src" / name
        if not src.is_file():
            continue
        data = src.read_bytes()
        if b"#pragma push" not in data:
            continue
        obj = u["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")
        if not (REPO / obj).is_file():
            continue
        defaults = kind_defaults(ninja_text, obj)
        lines = data.split(b"\n")
        fns = set(fn_positions(lines))

        stacks: dict[str, list] = {k: [] for k in KINDS}
        saves: list[dict] = []
        eff_at_fn: list[tuple[int, dict]] = []
        for idx, line in enumerate(lines, 1):
            m = PRAGMA_RE.match(line)
            if m:
                if m.group(1) == b"push":
                    saves.append(copy.deepcopy(stacks))
                elif m.group(1) == b"pop":
                    if saves:
                        stacks = saves.pop()
                else:
                    kind = m.group(2).decode()
                    val = m.group(3).decode()
                    if val == "reset":
                        if stacks[kind]:
                            stacks[kind].pop()
                    else:
                        stacks[kind].append(val)
                continue
            if idx in fns:
                eff = {k: (stacks[k][-1] if stacks[k] else defaults[k])
                       for k in KINDS}
                eff_at_fn.append((idx, eff))

        cur = dict(defaults)
        inserts: dict[int, list[bytes]] = {}
        for line_no, eff in eff_at_fn:
            pre = []
            for k in KINDS:
                if eff[k] != cur[k]:
                    if eff[k] is None:
                        pre.append(f"#pragma {k} reset".encode())
                    else:
                        pre.append(f"#pragma {k} {eff[k]}".encode())
                    cur[k] = eff[k]
            if pre:
                inserts[line_no] = pre

        n_before = sum(1 for l in lines if PRAGMA_RE.match(l))
        n_after = sum(len(v) for v in inserts.values())
        print(f"{name}: {n_before} -> {n_after}")
        if not args.apply:
            continue

        out = []
        for idx, l in enumerate(lines, 1):
            if PRAGMA_RE.match(l):
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
            applied += 1
        else:
            src.write_bytes(data)
            subprocess.run(["ninja", obj], cwd=REPO, capture_output=True)
            if hashlib.md5((REPO / obj).read_bytes()).hexdigest() != before_md5:
                raise SystemExit(f"RESTORE FAILED: {name}")
            print("  REVERTED")
            reverted += 1
    print(f"\napplied {applied}, reverted {reverted}")


if __name__ == "__main__":
    main()
