"""Consolidate a dll unit's scheduling/peephole pragmas to the MINIMUM: choose
the unit cflags whose default state matches the MAJORITY of the unit's
functions, strip every sched/peep pragma, and re-emit minimal `#pragma X on|off`
transitions only for the minority functions that differ. Uniform units reach
ZERO sched/peep pragmas (cflags carries the whole unit).

Atomic + byte-gated: the configure.py cflags edit, the source rewrite, and the
build.ninja regen are applied together; the unit .o is rebuilt and compared to
the pre-change bytes. On any mismatch/build failure BOTH configure.py and the
source are reverted and build.ninja regenerated, so matching % cannot regress.

Only operates on `main/dll/*.c` units (section default = cflags_base; the four
target vars are cflags_base / cflags_dll_noopt / cflags_dll_nosched /
cflags_dll_nopeep). Other pragma kinds (dont_inline, opt_*, fp_contract) are
left untouched. Files with #pragma push/pop are skipped (use pragma_depushpop
first).

Usage:
  python3 tools/pragma_consolidate.py [--apply] [--list FILE] [--filter SUBSTR]
  --list FILE : newline-separated src/ paths to restrict to (a worker partition)
Without --apply: dry-run (per unit: current cflags + pragma count -> target).
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
from pragma_audit import map_fn_states  # noqa: E402

PRAGMA_LINE = re.compile(rb"^\s*#pragma\s+(scheduling|peephole)\s+(on|off|reset)\s*$")
# (sched, peep) -> cflags var ; cflags_base is the dll section default
COMBO_VAR = {
    ("on", "on"): "cflags_base",
    ("off", "off"): "cflags_dll_noopt",
    ("off", "on"): "cflags_dll_nosched",
    ("on", "off"): "cflags_dll_nopeep",
}


def ninja_default(ninja_text: str, obj: str) -> tuple[str, str] | None:
    i = ninja_text.find(f"build {obj}:")
    if i < 0:
        return None
    block = ninja_text[i:ninja_text.find("\nbuild ", i + 1)]
    return ("off" if "noschedule" in block else "on",
            "off" if "nopeephole" in block else "on")


def set_cflags(cfg: str, unit_name: str, var: str) -> str | None:
    """Rewrite the Object(...) line for unit_name to use cflags=var (or drop the
    override when var is the section default cflags_base). Returns new cfg or
    None if the line wasn't found / already correct."""
    esc = re.escape(unit_name)
    # match the whole Object(...) call for this unit on one line
    pat = re.compile(r'(Object\([^,]+,\s*"' + esc + r'")([^\n]*?)(\))')
    m = pat.search(cfg)
    if not m:
        return None
    head, mid, tail = m.group(1), m.group(2), m.group(3)
    # strip any existing cflags=... kwarg from mid
    mid_clean = re.sub(r',\s*cflags=cflags_[A-Za-z0-9_]+', '', mid)
    if var == "cflags_base":
        new_call = head + mid_clean + tail
    else:
        new_call = head + mid_clean + f", cflags={var}" + tail
    if new_call == m.group(0):
        return None
    return cfg[:m.start()] + new_call + cfg[m.end():]


def regen() -> bool:
    r = subprocess.run([sys.executable, "configure.py"], cwd=REPO,
                       capture_output=True, text=True, timeout=120)
    return r.returncode == 0


def build(obj: str) -> bool:
    r = subprocess.run(["ninja", obj], cwd=REPO, capture_output=True, timeout=300)
    return b"FAILED" not in r.stdout + r.stderr


def md5(p: Path) -> str:
    return hashlib.md5(p.read_bytes()).hexdigest()


def minimal_source(data: bytes, fnmap: dict, cur_default: tuple[str, str],
                   target_default: tuple[str, str]) -> bytes:
    """Strip sched/peep pragmas; emit transitions relative to target_default."""
    seq = sorted((line, s, p) for (line, s, p) in fnmap.values())
    inserts: dict[int, list[bytes]] = {}
    cur = target_default
    for line, s, p in seq:
        eff = (cur_default[0] if s == "def-on" else s,
               cur_default[1] if p == "def-on" else p)
        pre = []
        if eff[0] != cur[0]:
            pre.append(b"#pragma scheduling " + eff[0].encode())
        if eff[1] != cur[1]:
            pre.append(b"#pragma peephole " + eff[1].encode())
        if pre:
            inserts[line] = pre
        cur = eff
    out = []
    for idx, l in enumerate(data.split(b"\n"), 1):
        if PRAGMA_LINE.match(l):
            continue
        if idx in inserts:
            out.extend(inserts[idx])
        out.append(l)
    return b"\n".join(out)


def process(name: str, obj: str, ninja_text: str, apply: bool) -> str:
    src = REPO / "src" / name
    if not src.is_file():
        return ""
    data = src.read_bytes()
    pragmas = [l for l in data.split(b"\n") if PRAGMA_LINE.match(l)]
    if not pragmas:
        return ""
    if b"#pragma push" in data or b"#pragma pop" in data:
        return f"SKIP push/pop: {name}"
    cur_default = ninja_default(ninja_text, obj)
    if cur_default is None or not (REPO / obj).is_file():
        return f"SKIP no-obj: {name}"
    fnmap = map_fn_states(src)
    if not fnmap:
        return f"SKIP no-fns: {name}"
    # absolute (sched,peep) per fn -> majority combo
    counts: dict[tuple[str, str], int] = {}
    for line, s, p in fnmap.values():
        eff = (cur_default[0] if s == "def-on" else s,
               cur_default[1] if p == "def-on" else p)
        counts[eff] = counts.get(eff, 0) + 1
    target = max(counts, key=lambda k: counts[k])
    var = COMBO_VAR[target]
    n_after = 0
    cur = target
    for line, s, p in sorted((l, s, p) for (l, s, p) in fnmap.values()):
        eff = (cur_default[0] if s == "def-on" else s,
               cur_default[1] if p == "def-on" else p)
        n_after += (eff[0] != cur[0]) + (eff[1] != cur[1])
        cur = eff
    summary = (f"{name}: {len(pragmas)} pragmas, {len(fnmap)} fns, "
               f"majority={target} -> {var}, after={n_after}")
    if not apply:
        return summary

    cfg_path = REPO / "configure.py"
    cfg = cfg_path.read_text()
    new_cfg = set_cflags(cfg, name, var)
    base_md5 = md5(REPO / obj)
    new_src = minimal_source(data, fnmap, cur_default, target)
    if new_src == data and new_cfg is None:
        return summary + " (already minimal)"

    src.write_bytes(new_src)
    if new_cfg is not None:
        cfg_path.write_text(new_cfg)
        if not regen():
            cfg_path.write_text(cfg)
            src.write_bytes(data)
            regen()
            return f"{name}: REVERT (configure regen failed)"
    ok = build(obj) and md5(REPO / obj) == base_md5
    if ok:
        return summary + " [APPLIED]"
    # revert both
    src.write_bytes(data)
    if new_cfg is not None:
        cfg_path.write_text(cfg)
        regen()
    if not build(obj) or md5(REPO / obj) != base_md5:
        raise SystemExit(f"RESTORE FAILED: {name}")
    return f"{name}: REVERTED (byte change)"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--list", default="")
    ap.add_argument("--filter", default="")
    args = ap.parse_args()

    allow = None
    if args.list:
        allow = {l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()}

    ninja_text = (REPO / "build.ninja").read_text(errors="replace")
    import json
    config = json.loads((REPO / "build" / "GSAE01" / "config.json").read_text())
    applied = reverted = 0
    for u in config["units"]:
        name = u["name"].replace("\\", "/")
        if not name.startswith("main/dll/"):
            continue
        if args.filter and args.filter not in name:
            continue
        if allow is not None and f"src/{name}" not in allow:
            continue
        obj = u["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")
        # build.ninja is regenerated mid-loop on cflags flips; re-read it
        if args.apply:
            ninja_text = (REPO / "build.ninja").read_text(errors="replace")
        r = process(name, obj, ninja_text, args.apply)
        if r:
            print(r, flush=True)
            if "[APPLIED]" in r:
                applied += 1
            elif "REVERTED" in r:
                reverted += 1
    if args.apply:
        print(f"\napplied {applied}, reverted {reverted}")


if __name__ == "__main__":
    main()
