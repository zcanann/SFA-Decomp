#!/usr/bin/env python3
"""Build the GC/2.0 reference-asm corpus.

For every reference project in `recipes.py`, compile each C unit with MWCC GC/2.0 across
the four peephole x scheduling profiles and disassemble each object with `objdump -M gekko`.
Output lands under build/refcorpus/<project>/<profile>/<src>.{o,s}. Best-effort: a unit that
won't compile under GC/2.0 is logged (coverage.json) and skipped, never fatal.

    python3 tools/refcorpus/build_corpus.py                 # all projects, all profiles
    python3 tools/refcorpus/build_corpus.py --projects dkr  # one project
    python3 tools/refcorpus/build_corpus.py --jobs 8 --force
    python3 tools/refcorpus/build_corpus.py --list-fails    # after a run, show why units failed

Run `search_corpus.py` afterwards to query the result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recipes as R  # noqa: E402

FUNC_LABEL_RE = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:")


def _rel_subdirs_with_headers(root: Path, sub: str) -> List[str]:
    """Every directory under root/<sub> that holds a header, as repo-relative -i dirs.

    N64 sources include siblings by bare name (`#include "reset.h"` from src/usb/), so we
    add each such dir to the search path.
    """
    base = root / sub
    if not base.is_dir():
        return []
    dirs = set()
    for h in base.rglob("*.h"):
        dirs.add(h.parent)
    return [str(d.relative_to(R.REPO_ROOT)) for d in sorted(dirs)]


def _write_generated_headers(rec: R.Recipe) -> Optional[str]:
    """Run the recipe's stub generator; return the repo-relative gen dir (or None)."""
    if not rec.gen:
        return None
    gen = R.GENERATORS[rec.gen](rec)
    gen_dir = R.REPO_ROOT / R.GEN_ROOT / rec.name
    gen_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in gen.items():
        (gen_dir / fname).write_text(content)
    return str((R.REPO_ROOT / R.GEN_ROOT / rec.name).relative_to(R.REPO_ROOT))


def _include_args(rec: R.Recipe, gen_dir: Optional[str]) -> List[str]:
    args: List[str] = []
    rel_root = str(rec.abs_root.relative_to(R.REPO_ROOT))  # e.g. reference_projects/dkr
    if gen_dir:
        args += ["-i", gen_dir]
    for d in rec.include_dirs:
        p = (rel_root + "/" + d).rstrip("/") if d else rel_root
        args += ["-i", p]
    if rec.auto_src_subdirs:
        for d in _rel_subdirs_with_headers(rec.abs_root, "src"):
            args += ["-i", d]
    return args


def _enumerate_sources(rec: R.Recipe) -> List[str]:
    excl = [re.compile(p) for p in rec.exclude_res]
    seen: set[str] = set()
    out: List[str] = []
    for g in rec.src_globs:
        for p in sorted(rec.abs_root.glob(g)):
            rel = str(p.relative_to(R.REPO_ROOT))
            if rel in seen:
                continue
            if any(e.search("/" + str(p.relative_to(rec.abs_root))) for e in excl):
                continue
            seen.add(rel)
            out.append(rel)
    return out


def _base_argv(rec: R.Recipe, gen_dir: Optional[str], profile_flags: List[str]) -> List[str]:
    argv = [R.WIBO, R.COMPILER] + list(R.BASE_CFLAGS)
    if rec.char_unsigned:
        argv += ["-char", "unsigned"]
    if rec.use_shim:
        argv += ["-prefix", R.SHIM]
    argv += ["-maxerrors", "1"]
    argv += _include_args(rec, gen_dir)
    for d in rec.defines:
        argv += ["-D" + d]
    argv += list(profile_flags)
    return argv


def _reason_from_stderr(text: str) -> str:
    """One-line human reason from an mwcc error dump."""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if "Error:" in ln:
            # the descriptive message is usually the next non-caret '#  ' line
            for j in range(i, min(i + 3, len(lines))):
                m = re.sub(r"^#\s*", "", lines[j]).strip()
                if m and "Error:" not in m and set(m) - set("^ "):
                    return m[:120]
    for ln in lines:
        m = re.sub(r"^#\s*", "", ln).strip()
        if m and set(m) - set("^ #"):
            return m[:120]
    return "unknown error"


# --- worker (module-level for multiprocessing) --------------------------------

_JOB_CTX: Dict = {}


def _init_worker(base_argvs: Dict, cache_key_extra: Dict):
    _JOB_CTX["argvs"] = base_argvs
    _JOB_CTX["extra"] = cache_key_extra


def _compile_one(job: Dict) -> Dict:
    rec_name, profile, src = job["rec"], job["profile"], job["src"]
    argv = list(_JOB_CTX["argvs"][(rec_name, profile)])
    out_o = job["out_o"]
    out_s = job["out_s"]
    Path(out_o).parent.mkdir(parents=True, exist_ok=True)

    # cache: (source bytes, full argv, compiler size, shim+gen key)
    try:
        src_bytes = Path(src).read_bytes()
    except OSError:
        return {**job, "ok": False, "nfuncs": 0, "reason": "source unreadable"}
    key = hashlib.sha1()
    key.update(src_bytes)
    key.update(("\0".join(argv)).encode())
    key.update(str(_JOB_CTX["extra"].get(rec_name, "")).encode())
    digest = key.hexdigest()
    hash_path = Path(out_o + ".hash")
    if hash_path.exists() and hash_path.read_text() == digest \
            and Path(out_s).exists() and Path(out_o).exists():
        n = sum(1 for _ in open(out_s) if FUNC_LABEL_RE.match(_))
        return {**job, "ok": True, "nfuncs": n, "reason": "", "cached": True}

    full = argv + ["-c", src, "-o", out_o]
    proc = subprocess.run(full, cwd=str(R.REPO_ROOT), capture_output=True, text=True)
    if proc.returncode != 0 or not Path(out_o).exists():
        for stale in (out_o, out_s, str(hash_path)):
            try:
                os.remove(stale)
            except OSError:
                pass
        return {**job, "ok": False, "nfuncs": 0,
                "reason": _reason_from_stderr(proc.stdout + proc.stderr)}

    dis = subprocess.run([R.OBJDUMP, "-M", "gekko", "-drz", out_o],
                         cwd=str(R.REPO_ROOT), capture_output=True, text=True)
    Path(out_s).write_text(dis.stdout)
    hash_path.write_text(digest)
    n = sum(1 for ln in dis.stdout.splitlines() if FUNC_LABEL_RE.match(ln))
    return {**job, "ok": True, "nfuncs": n, "reason": "", "cached": False}


def build(projects: Optional[List[str]], profiles: List[str], jobs: int,
          force: bool, limit: Optional[int]) -> Dict:
    recs = R.resolve(projects)
    base_argvs: Dict = {}
    cache_extra: Dict = {}
    all_jobs: List[Dict] = []

    for rec in recs:
        gen_dir = _write_generated_headers(rec)
        # cache-bust key component: shim + generated header contents
        extra = ""
        if rec.use_shim:
            extra += (R.REPO_ROOT / R.SHIM).read_text()
        if gen_dir:
            for f in sorted((R.REPO_ROOT / gen_dir).glob("*")):
                extra += f.read_text()
        cache_extra[rec.name] = hashlib.sha1(extra.encode()).hexdigest()

        srcs = _enumerate_sources(rec)
        if limit:
            srcs = srcs[:limit]
        for profile in profiles:
            base_argvs[(rec.name, profile)] = _base_argv(rec, gen_dir, R.PROFILES[profile])
            for src in srcs:
                rel = str(Path(src).relative_to(rec.abs_root.relative_to(R.REPO_ROOT)))
                stem = f"{R.OUT_ROOT}/{rec.name}/{profile}/{rel}"
                all_jobs.append({
                    "rec": rec.name, "profile": profile, "src": src,
                    "out_o": stem[:-2] + ".o" if stem.endswith(".c") else stem + ".o",
                    "out_s": stem[:-2] + ".s" if stem.endswith(".c") else stem + ".s",
                })

    if force:
        for j in all_jobs:
            for f in (j["out_o"] + ".hash",):
                try:
                    os.remove(f)
                except OSError:
                    pass

    print(f"[refcorpus] {len(recs)} project(s), {len(profiles)} profile(s), "
          f"{len(all_jobs)} compile jobs, {jobs} workers")
    results: List[Dict] = []
    with mp.Pool(jobs, initializer=_init_worker, initargs=(base_argvs, cache_extra)) as pool:
        for i, res in enumerate(pool.imap_unordered(_compile_one, all_jobs, chunksize=4), 1):
            results.append(res)
            if i % 200 == 0:
                ok = sum(1 for r in results if r["ok"])
                print(f"  ... {i}/{len(all_jobs)}  ok={ok}")

    return _summarize(recs, profiles, results)


def _summarize(recs, profiles, results) -> Dict:
    built_projects = {r.name for r in recs}
    built_profiles = set(profiles)
    new_manifest = [{k: r[k] for k in ("rec", "profile", "src", "out_o", "out_s", "ok", "nfuncs")}
                    for r in results]
    (R.REPO_ROOT / R.OUT_ROOT).mkdir(parents=True, exist_ok=True)

    # merge with any prior manifest so a partial rebuild doesn't drop other projects
    man_path = R.REPO_ROOT / R.OUT_ROOT / "manifest.json"
    manifest = []
    if man_path.exists():
        manifest = [e for e in json.loads(man_path.read_text())
                    if not (e["rec"] in built_projects and e["profile"] in built_profiles)]
    manifest += new_manifest
    man_path.write_text(json.dumps(manifest, indent=1))

    cov_path = R.REPO_ROOT / R.OUT_ROOT / "coverage.json"
    cov: Dict = json.loads(cov_path.read_text()) if cov_path.exists() else {}
    for rec in recs:
        cov[rec.name] = {}
        for profile in profiles:
            rs = [r for r in results if r["rec"] == rec.name and r["profile"] == profile]
            ok = [r for r in rs if r["ok"]]
            fails = [{"src": r["src"], "reason": r["reason"]} for r in rs if not r["ok"]]
            cov[rec.name][profile] = {
                "files_total": len(rs), "files_ok": len(ok),
                "funcs": sum(r["nfuncs"] for r in ok), "fails": fails,
            }
    (R.REPO_ROOT / R.OUT_ROOT / "coverage.json").write_text(json.dumps(cov, indent=1))

    print("\n=== coverage (per project, profile 'both_off') ===")
    for name, per in cov.items():
        p = per.get("both_off") or next(iter(per.values()))
        pct = 100.0 * p["files_ok"] / p["files_total"] if p["files_total"] else 0.0
        print(f"  {name:5s}  {p['files_ok']:4d}/{p['files_total']:<4d} files "
              f"({pct:5.1f}%)   {p['funcs']:5d} funcs/profile")
    total_funcs = sum(pp["funcs"] for per in cov.values() for pp in per.values())
    print(f"  total asm samples across all profiles (full corpus): {total_funcs}")
    print(f"  wrote {R.OUT_ROOT}/manifest.json and coverage.json")
    return cov


def _list_fails():
    path = R.REPO_ROOT / R.OUT_ROOT / "coverage.json"
    if not path.exists():
        raise SystemExit("no coverage.json; run a build first")
    cov = json.loads(path.read_text())
    from collections import Counter
    for name, per in cov.items():
        prof = per.get("both_off") or next(iter(per.values()))
        reasons = Counter(f["reason"] for f in prof["fails"])
        print(f"\n### {name}: {len(prof['fails'])} failing units (profile both_off)")
        for reason, n in reasons.most_common():
            print(f"  {n:3d}  {reason}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--projects", help="comma list (default all): "
                    + ",".join(R.RECIPES))
    ap.add_argument("--profiles", default=",".join(R.PROFILES),
                    help="comma list of profiles (default all four)")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 4) - 2))
    ap.add_argument("--force", action="store_true", help="ignore cache")
    ap.add_argument("--limit", type=int, help="cap files per project (for testing)")
    ap.add_argument("--list-fails", action="store_true",
                    help="print failure-reason histogram from the last run and exit")
    args = ap.parse_args()

    if args.list_fails:
        _list_fails()
        return
    projects = args.projects.split(",") if args.projects else None
    profiles = [p for p in args.profiles.split(",") if p]
    for p in profiles:
        if p not in R.PROFILES:
            raise SystemExit(f"unknown profile '{p}'. known: {', '.join(R.PROFILES)}")
    build(projects, profiles, args.jobs, args.force, args.limit)


if __name__ == "__main__":
    main()
