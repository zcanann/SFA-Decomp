"""Per-FUNCTION optimization-flag prober: which functions of a unit match retail
under which -opt/-inline profile.

A "register permutation" divergence (identical instruction stream, different
register numbers) is frequently NOT an unsteerable allocator quirk: it is the
signature of a per-TU optimization flag that differs from the one retail used.
MWCC's copy/constant propagation pass in particular reorders the values the
register allocator sees, which permutes register homes without changing the
instruction sequence.

When different functions of one unit want DIFFERENT profiles, that is evidence
to audit its boundary against the DOL. It is not permission to split the unit:
a DOL-confirmed TU keeps one compiler profile even when some functions regress.

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

So this list is a TU-boundary audit worklist, not a flag or automatic split
worklist. A split requires independent DOL evidence. The units, with the number
of flag-fixable functions: player 11, lightmap 6, track_dolphin 3,
objprint_dolphin 2, dll_000F_unk 2, obj_movelib 2, and one each in textrender,
Hcurves, model, objprint, gametext, dll_0015_curves, objanim, skeetla_80139A8C,
object, dll_0272_hightop, shader_dolphin, sal_dsp, worldobj,
dll_0049_cameramodecombat, dlls/objects/201_Baddie/Baddie, fallladdersgroup.

METHOD WARNING: do not edit the tree or run ninja while a sweep is in flight.
This tool reads build.ninja and the unit source per unit, so a concurrent
configure.py or source edit silently changes what a later unit is compiled
from.  A first pass of this sweep was invalidated that way and reported 1
flag-fixable function in track_dolphin where a clean re-run found 3.
"""
from __future__ import annotations

import argparse
import os
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
#
# These REPLACE the unit's -opt wholesale, and every alternative hardcodes
# "nopeephole,noschedule".  That is safe only for units already configured that
# way -- i.e. main/ under GC/2.0.  See PROFILES_125N for why.
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

# RELATIVE profiles, used for units whose configured -opt is not already
# "nopeephole,noschedule" -- musyx/audio (GC/1.2.5n) configures plain -O4,p with
# NO -opt at all, i.e. peephole and scheduling ON.  Against those units the
# absolute table above is not a probe but a demolition: substitute() finds no
# -opt to replace, APPENDS "nopeephole,noschedule,...", and every alternative
# silently also turns two major passes off.  Measured, that yields a table where
# every alternative column is "-" for every function -- indistinguishable from a
# genuinely closed flag axis, which is the most dangerous failure a tool of this
# kind can have.  Here the tokens are ADDED to whatever the unit configures.
#
# The token set is the measured-LIVE vocabulary (see --census).  Unknown tokens
# are accepted and SILENTLY IGNORED by 1.2.5n exactly as w81 proved for GC/2.0,
# so a token earns its place here only by changing some unit's output.
#
# MEASURED 2026-08-05, AND IT IS THE SAME FAILURE THIS COMMENT WARNS ABOUT:
# at -O0 (the msl_math_o0_cflags units -- acosf, sincosf, math_8029454c) EVERY
# token below is BYTE-INERT.  All seven profiles were md5-verified to produce
# objects identical to the configured build, so this table prints an all-"-"
# column set that is indistinguishable from a closed axis -- while the axes that
# ARE live on those units, "peephole" and the -O level itself, are not probed at
# all.  Do not read an all-"-" table on an -O0 unit as evidence of anything; drop
# to a direct compile.  Adding peephole/-O columns here is the real fix.
PROFILES_125N: dict[str, tuple[str | None, str | None]] = {
    "as-configured":    (None, None),
    "peephole-off":     ("nopeephole", None),
    "nocse":            ("nocse", None),
    "noprop":           ("nopropagation", None),
    "nolifetimes":      ("nolifetimes", None),
    "noloopinv":        ("noloopinvariants", None),
    "nostrength":       ("nostrength", None),
    "nodead":           ("nodead", None),
    "nocse+noprop":     ("nocse,nopropagation", None),
    "noloopinv+nodead": ("noloopinvariants,nodead", None),
}

# Tokens probed by --census.  The first is a deliberate nonsense token: it is
# the negative control for silent-unknown-token acceptance and MUST come out
# "inert".  The trailing positive forms are already on at -O4,p, so "inert" for
# them means "no observable effect here", not "rejected".
CENSUS_TOKENS = [
    "__BOGUS__",
    "nopeephole", "noschedule", "nocse", "nopropagation", "nolifetimes",
    "noloopinvariants", "nostrength", "nodead",
    "noautoinline", "nofp_contract", "nointrinsics", "noaliasing", "novectorize",
    "peephole", "schedule", "cse", "propagation", "lifetimes", "loopinvariants",
    "strength", "dead",
]


def ninja_cflags(obj_path: str) -> tuple[list[str], str]:
    """Recover the exact cflags ninja uses for one object, plus its mw_version."""
    text = (REPO / "build.ninja").read_text()
    # ninja writes native separators; on Windows that is backslashes while the
    # objdiff config we derive obj_path from uses forward slashes.
    for cand in (obj_path, obj_path.replace("/", "\\")):
        idx = text.find(f"build {cand}: ")
        if idx != -1:
            break
    else:
        raise SystemExit(f"no build statement for {obj_path} in build.ninja")
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


def substitute(flags: list[str], opt: str | None, inline: str | None,
               relative: bool = False) -> list[str]:
    """Apply an -opt/-inline override.

    relative=False replaces the effective -opt outright (the historical
    behaviour, correct for units already configured nopeephole,noschedule).
    relative=True ADDS the tokens to whatever the unit configures, preserving
    its peephole/scheduling state -- required for any unit whose baseline is
    not nopeephole,noschedule, or the "probe" changes several axes at once.
    """
    out = list(flags)
    for key, val in (("-opt", opt), ("-inline", inline)):
        if val is None:
            continue
        positions = [i for i, flag in enumerate(out[:-1]) if flag == key]
        if positions:
            # Later MWCC options override earlier ones.  Some profiles append
            # an override to cflags_base, so replace the effective occurrence.
            if relative and key == "-opt":
                out[positions[-1] + 1] = f"{out[positions[-1] + 1]},{val}"
            else:
                out[positions[-1] + 1] = val
        else:
            out += [key, val]
    return out


def wants_relative(flags: list[str]) -> bool:
    """A unit needs relative profiles unless it already configures the
    nopeephole,noschedule baseline the absolute table assumes."""
    positions = [i for i, flag in enumerate(flags[:-1]) if flag == "-opt"]
    if not positions:
        return True
    configured = flags[positions[-1] + 1]
    toks = set(configured.split(","))
    return not {"nopeephole", "noschedule"} <= toks


def compile_probe(src: str, flags: list[str], mwv: str, outdir: Path) -> Path | None:
    outdir.mkdir(parents=True, exist_ok=True)
    # wibo is the Linux loader for the Windows-native compiler; on Windows the
    # ninja rules invoke sjiswrap.exe/mwcceppc.exe directly (see build.ninja).
    cmd = [] if os.name == "nt" else [str(REPO / "build/tools/wibo")]
    cmd += [
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
    ap.add_argument("--profiles", default=None)
    ap.add_argument("--census", action="store_true",
                    help="probe each -opt token alone for LIVENESS (does it change output?) "
                         "and for CONTROL RETENTION, instead of running profiles")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--relative", dest="relative", action="store_true", default=None,
                      help="ADD profile tokens to the unit's configured -opt (default for any "
                           "unit not already configured nopeephole,noschedule)")
    mode.add_argument("--absolute", dest="relative", action="store_false",
                      help="REPLACE the unit's -opt outright")
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

    relative = wants_relative(flags) if args.relative is None else args.relative
    table = PROFILES_125N if relative else PROFILES
    outroot = REPO / "build/flag_probe_fn"

    def want_bytes(sym: str) -> list | None:
        try:
            return [b for b, _ in disassemble(objdump, target, sym)]
        except LookupError:
            return None

    if args.census:
        base = compile_probe(src, flags, mwv, outroot / "_census_base")
        if base is None:
            print("baseline compile FAILED -- cannot census")
            return 2

        def got_bytes(obj, sym):
            try:
                return [b for b, _ in disassemble(objdump, obj, sym)]
            except LookupError:
                return None

        ctrl = [s for s in symbols
                if want_bytes(s) is not None and got_bytes(base, s) == want_bytes(s)]
        print(f"unit {args.unit}   mw_version={mwv}   symbols={len(symbols)}   "
              f"as-configured controls={len(ctrl)}")
        print("A token is LIVE only if it changes output.  __BOGUS__ is the negative control "
              "for silent-unknown-token acceptance and MUST read inert.\n")
        print(f"{'token':24}{'live?':8}{'controls kept':16}note")
        for tok in CENSUS_TOKENS:
            obj = compile_probe(src, substitute(flags, tok, None, relative=True),
                                mwv, outroot / "_census_tok")
            if obj is None:
                print(f"{tok:24}{'ERR':8}{'-':16}compile failed / token rejected")
                continue
            live = any(got_bytes(obj, s) != got_bytes(base, s) for s in symbols)
            kept = sum(1 for s in ctrl if got_bytes(obj, s) == want_bytes(s))
            note = "" if live else "IGNORED (silent-unknown, or already-on no-op)"
            print(f"{tok:24}{'LIVE' if live else 'inert':8}"
                  f"{f'{kept}/{len(ctrl)}':16}{note}")
        return 0

    names = [p for p in (args.profiles.split(",") if args.profiles else list(table))
             if p in table]
    results: dict[str, dict[str, str]] = {}
    for pname in names:
        opt, inline = table[pname]
        obj = compile_probe(src, substitute(flags, opt, inline, relative=relative),
                            mwv, outroot / pname)
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
    print(f"mw_version={mwv}   profiles={'RELATIVE (added to configured -opt)' if relative else 'ABSOLUTE (replace -opt)'}")
    print(f"{'function':{width}}" + "".join(f"{n:>16}" for n in names))
    for sym in symbols:
        row = results[sym]
        cells = "".join(f"{row.get(n, '?'):>16}" for n in names)
        print(f"{sym:{width}}{cells}")

    cfg = names[0] if names and names[0] == "as-configured" else None

    # Existing matches measure the cost of an alternative profile. Losing them
    # does not invalidate a successful compile or an exact function comparison;
    # keeping only one does not make a whole-TU change safe either.
    controls = [s for s in symbols if results[s].get(cfg) == "MATCH"] if cfg else []
    if controls:
        kept = {n: sum(1 for s in controls if results[s].get(n) == "MATCH") for n in names}
        print(f"\n{'CONTROLS kept':{width}}" +
              "".join(f"{f'{kept[n]}/{len(controls)}':>16}" for n in names))
        for n in names:
            if n == cfg:
                continue
            lost = [s for s in controls if results[s].get(n) != "MATCH"]
            if lost:
                print(f"  {n} loses existing matches: {', '.join(lost)}")

    alternatives = [n for n in names if n != cfg]
    gained = [s for s in symbols
              if results[s].get(cfg) != "MATCH"
              and any(results[s].get(n) == "MATCH" for n in alternatives)]
    if gained:
        print("\nFunctions exact under an alternative profile (whole-TU review required):")
        for s in gained:
            wins = [n for n in alternatives if results[s].get(n) == "MATCH"]
            print(f"  {s:{width}} <- {','.join(wins)}")
        print("  These results identify transformations to inspect; they do not prove source "
              "recovery is exhausted, the configured profile is wrong, or a TU split is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
