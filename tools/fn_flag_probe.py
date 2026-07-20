"""Per-FUNCTION optimization-flag prober: which functions of a unit match retail
under which -opt/-inline profile.

A "register permutation" divergence (identical instruction stream, different
register numbers) is frequently NOT an unsteerable allocator quirk: it is the
signature of a per-TU optimization flag that differs from the one retail used.
MWCC's copy/constant propagation pass in particular reorders the values the
register allocator sees, which permutes register homes without changing the
instruction sequence.

When different functions of one unit want DIFFERENT profiles, that unit merges
two or more original translation units and needs a SPLIT, not a source edit.

Usage:
  python3 tools/fn_flag_probe.py <unit>                  probe all sub-100 functions
  python3 tools/fn_flag_probe.py <unit> --all            probe every function
  python3 tools/fn_flag_probe.py <unit> --symbol NAME    probe one function
  python3 tools/fn_flag_probe.py <unit> --profiles a,b   restrict profiles

Gates on EXTRACTED FUNCTION BYTES (never on tool silence or on a build that
failed): a profile whose compile fails is reported as ERR, never as a match.

Sweep result (wave 92, all 154 units carrying a sub-100 function, 7 profiles):
42 functions across 22 units reach byte-identical under some profile other than
the one their unit is configured with.  Every one of those 22 units is a MIXED
population -- no unit-wide flag flip is a net win, because the profile that
fixes those functions breaks others in the same unit.  Two flips raise the
count of byte-identical functions yet LOWER the unit's fuzzy_match_percent
(the truth metric), so both were rejected:

    main/lightmap.c   -opt nopeephole,noschedule -inline noauto
                      36 -> 40 functions at 100, unit 99.186 -> 98.528
    main/objanim.c    -opt nopeephole,noschedule,nocse
                      10 -> 11 functions at 100, unit 99.405 -> 98.897

So this list is a TU-SPLIT worklist, not a flag worklist.  The units, with the
number of flag-fixable functions: player 11, lightmap 6, track_dolphin 3,
objprint_dolphin 2, dll_000F_unk 2, obj_movelib 2, and one each in textrender,
Hcurves, model, objprint, gametext, dll_0015_curves, objanim, skeetla_80139A8C,
object, dll_0272_hightop, shader_dolphin, sal_dsp, worldobj,
dll_0049_cameramodecombat, dll_00C9_enemy, fallladdersgroup.

METHOD WARNING: do not edit the tree or run ninja while a sweep is in flight.
This tool reads build.ninja and the unit source per unit, so a concurrent
configure.py or source edit silently changes what a later unit is compiled
from.  A first pass of this sweep was invalidated that way and reported 1
flag-fixable function in track_dolphin where a clean re-run found 3.
"""
from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fnbytes import disassemble, find_unit, objdump_path
from function_objdump import load_units

REPO = Path(__file__).resolve().parent.parent

# name -> (-opt token, -inline token).  None keeps the unit's configured value.
PROFILES: dict[str, tuple[str | None, str | None]] = {
    "as-configured":  (None, None),
    "prop":           ("nopeephole,noschedule", None),
    "noprop":         ("nopeephole,noschedule,nopropagation", None),
    "nocse":          ("nopeephole,noschedule,nocse", None),
    "nocse+noprop":   ("nopeephole,noschedule,nocse,nopropagation", None),
    "noprop+noauto":  ("nopeephole,noschedule,nopropagation", "noauto"),
    "prop+noauto":    ("nopeephole,noschedule", "noauto"),
    "noprop+inloff":  ("nopeephole,noschedule,nopropagation", "off"),
    "prop+inloff":    ("nopeephole,noschedule", "off"),
}


def ninja_cflags(obj_path: str) -> tuple[list[str], str]:
    """Recover the exact cflags ninja uses for one object, plus its mw_version."""
    text = (REPO / "build.ninja").read_text()
    marker = f"build {obj_path}: "
    idx = text.index(marker)
    # the build statement runs until the next line that starts a new 'build '/'rule '
    end = len(text)
    for m in re.finditer(r"^(?:build|rule) ", text[idx + 1 :], re.M):
        end = idx + 1 + m.start()
        break
    block = text[idx:end].replace("$\n", " ")
    cflags = re.search(r"^\s*cflags\s*=\s*(.*)$", block, re.M)
    mwv = re.search(r"^\s*mw_version\s*=\s*(\S+)\s*$", block, re.M)
    if not cflags or not mwv:
        raise SystemExit(f"could not recover cflags for {obj_path}")
    return shlex.split(cflags.group(1)), mwv.group(1)


def substitute(flags: list[str], opt: str | None, inline: str | None) -> list[str]:
    out = list(flags)
    for key, val in (("-opt", opt), ("-inline", inline)):
        if val is None:
            continue
        if key in out:
            out[out.index(key) + 1] = val
        else:
            out += [key, val]
    return out


def compile_probe(src: str, flags: list[str], mwv: str, outdir: Path) -> Path | None:
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(REPO / "build/tools/wibo"),
        str(REPO / "build/tools/sjiswrap.exe"),
        str(REPO / f"build/compilers/{mwv}/mwcceppc.exe"),
        *flags, "-c", src, "-o", str(outdir),
    ]
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    obj = outdir / (Path(src).stem + ".o")
    return obj if obj.is_file() and proc.returncode == 0 else None


def sub100_symbols(report_unit_name: str) -> list[str]:
    import json
    report = json.loads((REPO / "build/GSAE01/report.json").read_text())
    for unit in report["units"]:
        if unit["name"].endswith(report_unit_name):
            return [f["name"] for f in (unit.get("functions") or [])
                    if 0 < f.get("fuzzy_match_percent", 0) < 100]
    return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("unit")
    ap.add_argument("--symbol", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--profiles", default=",".join(PROFILES))
    args = ap.parse_args()

    units = load_units(REPO / "build/GSAE01/config.json")
    unit = find_unit(units, args.unit)
    target = REPO / unit["object"]
    src = unit["name"]
    if not Path(REPO / src).is_file():
        src = "src/" + src
    obj_rel = unit["object"].replace("build/GSAE01/obj/", "build/GSAE01/src/")
    flags, mwv = ninja_cflags(obj_rel)
    objdump = objdump_path()

    stem = Path(src).stem
    symbols = args.symbol or sub100_symbols(stem) or []
    if args.all or not symbols:
        proc = subprocess.run([str(objdump), "-t", str(target)], capture_output=True, text=True)
        symbols = sorted({m.group(1) for m in
                          re.finditer(r"^[0-9a-f]+\s+g?\s*F\s+\.text\s+[0-9a-f]+\s+(\S+)$",
                                      proc.stdout, re.M)})
    if not symbols:
        print("no symbols to probe")
        return 2

    names = [p for p in args.profiles.split(",") if p in PROFILES]
    results: dict[str, dict[str, str]] = {}
    outroot = REPO / "build/flag_probe_fn"
    for pname in names:
        opt, inline = PROFILES[pname]
        obj = compile_probe(src, substitute(flags, opt, inline), mwv, outroot / pname)
        for sym in symbols:
            if obj is None:
                results.setdefault(sym, {})[pname] = "ERR"
                continue
            try:
                want = [b for b, _ in disassemble(objdump, target, sym)]
                got = [b for b, _ in disassemble(objdump, obj, sym)]
            except LookupError:
                results.setdefault(sym, {})[pname] = "ERR"
                continue
            if not want or not got:
                results.setdefault(sym, {})[pname] = "ERR"
            else:
                results.setdefault(sym, {})[pname] = "MATCH" if want == got else "-"

    width = max(len(s) for s in symbols) + 2
    print(f"{'function':{width}}" + "".join(f"{n:>16}" for n in names))
    for sym in symbols:
        row = results[sym]
        cells = "".join(f"{row.get(n, '?'):>16}" for n in names)
        print(f"{sym:{width}}{cells}")

    cfg = names[0] if names and names[0] == "as-configured" else None
    gained = [s for s in symbols
              if results[s].get(cfg) != "MATCH"
              and any(results[s].get(n) == "MATCH" for n in names)]
    if gained:
        print("\nfunctions a DIFFERENT profile would fix "
              "(=> per-TU flag is wrong, or the unit merges TUs and needs a split):")
        for s in gained:
            wins = [n for n in names if results[s].get(n) == "MATCH"]
            print(f"  {s:{width}} <- {','.join(wins)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
