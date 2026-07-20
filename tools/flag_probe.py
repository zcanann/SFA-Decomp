#!/usr/bin/env python3
"""Per-TU compiler-flag probe.

Recompiles one unit with EXTRA flag tokens appended to its real ninja compile
command (later MWCC flags override earlier ones) into a scratch object, then
rescores it per-function against the retail object via a single-unit objdiff
project.  No config edit, no tree mutation.

  python3 tools/flag_probe.py <unit> ["<extra flags>" ...]

An empty extra-flag string is the baseline.  Use `-opt display` in the extra
flags to have MWCC print the resolved optimizer state (live-token oracle).
"""
import json, os, shlex, subprocess, sys, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = os.environ.get("FLAG_PROBE_DIR",
                         os.path.join(ROOT, "build", "flag_probe"))
os.makedirs(SCRATCH, exist_ok=True)

OBJDIFF = json.load(open(os.path.join(ROOT, "objdiff.json")))
UNITS = {u["name"]: u for u in OBJDIFF["units"]}

_CMD_CACHE = {}


def base_cmd(unitname):
    """The mwcc part of the unit's real ninja compile command."""
    if unitname in _CMD_CACHE:
        return _CMD_CACHE[unitname]
    objp = UNITS[unitname]["base_path"]
    out = subprocess.run(["ninja", "-t", "commands", objp], cwd=ROOT,
                         capture_output=True, text=True)
    lines = [l for l in out.stdout.strip().split("\n") if "mwcceppc.exe" in l]
    if not lines:
        raise SystemExit("no mwcc compile command for " + objp)
    cmd = lines[-1].split(" && ")[0]
    _CMD_CACHE[unitname] = cmd
    return cmd


def compile_probe(unitname, extra, tag):
    """extra: string of additional flags appended before -c.  Returns (obj, err)."""
    toks = shlex.split(base_cmd(unitname))
    toks = [t for t in toks if t != "-MMD"]
    ci = toks.index("-c")
    toks[ci:ci] = shlex.split(extra or "")
    outdir = os.path.join(SCRATCH, tag)
    os.makedirs(outdir, exist_ok=True)
    toks[toks.index("-o") + 1] = outdir
    r = subprocess.run(toks, cwd=ROOT, capture_output=True, text=True)
    src = toks[toks.index("-c") + 1]
    o = os.path.join(outdir, os.path.basename(src)[:-2] + ".o")
    log = r.stdout + r.stderr
    if r.returncode != 0 or not os.path.exists(o):
        return None, log[-2000:]
    # Only an UNKNOWN token is fatal: MWCC silently ignores it, so the probe
    # would report a meaningless null.  "Option overrides previously specified
    # optimization" is benign and expected when appending an override.
    if "Unknown option" in log:
        return None, "IGNORED-FLAG: " + log[-800:]
    return o, None


def score(unitname, objpath):
    """Returns ((unit_fuzzy, {fn: fuzzy}), None) or (None, err)."""
    u = json.loads(json.dumps(UNITS[unitname]))
    u["base_path"] = os.path.abspath(objpath)
    u["target_path"] = os.path.join(ROOT, u["target_path"])
    u.pop("scratch", None)
    cfg = {"min_version": OBJDIFF["min_version"], "units": [u],
           "progress_categories": OBJDIFF.get("progress_categories", [])}
    key = hashlib.md5((unitname + objpath).encode()).hexdigest()[:10]
    d0 = os.path.join(SCRATCH, "proj_" + key)
    os.makedirs(d0, exist_ok=True)
    p = os.path.join(d0, "objdiff.json")
    json.dump(cfg, open(p, "w"))
    outp = p + ".report"
    r = subprocess.run(["build/tools/objdiff-cli", "report", "generate",
                        "-p", d0, "-o", outp], cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, (r.stdout + r.stderr)[-1500:]
    un = json.load(open(outp))["units"][0]
    if "fuzzy_match_percent" not in un.get("measures", {}):
        return None, "no-measures"
    fns = {f["name"]: float(f.get("fuzzy_match_percent", 0.0))
           for f in un.get("functions", [])}
    return (float(un["measures"]["fuzzy_match_percent"]), fns), None


def probe(unitname, extra, tag):
    ob, err = compile_probe(unitname, extra, tag)
    if ob is None:
        return None, err
    return score(unitname, ob)


if __name__ == "__main__":
    unit = sys.argv[1]
    variants = sys.argv[2:] or [""]
    base = None
    for i, ex in enumerate(variants):
        s, err = probe(unit, ex, "cli%d_%s" % (i, os.getpid()))
        if s is None:
            print("FAIL %r: %s" % (ex, err))
            continue
        tot, fns = s
        print("=== %r total=%.6f" % (ex, tot))
        if base is None:
            base = fns
            for k, v in sorted(fns.items()):
                print("   %-46s %.6f" % (k, v))
        else:
            for k, v in sorted(fns.items()):
                b = base.get(k, 0.0)
                if abs(v - b) > 1e-6:
                    print("   %-46s %.6f -> %.6f  %+.6f" % (k, b, v, v - b))
