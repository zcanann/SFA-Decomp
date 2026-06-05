#!/usr/bin/env python3
"""Search MP4's matched-100% binaries for specific asm patterns, then show
the C that produced them.

MP4 is 100% byte-matched against the original game, so every function in
MP4's .o files is a *definitive* C↔asm pair for whatever MWCC quirk made
that instruction. When SFA needs a specific asm shape (rlwimi at a given
bit position, cmplwi on a u16 field, fnmadds vs fmul+fneg, etc.), search
MP4 for an example and read the C that produced it.

Usage:
    python3 tools/mp4_asm_search.py "rlwimi"                 # find any rlwimi
    python3 tools/mp4_asm_search.py "rlwimi.*,5,26,26"        # specific bit pos
    python3 tools/mp4_asm_search.py "cntlzw" --context 8      # wider asm context
    python3 tools/mp4_asm_search.py "psq_st" --max 5          # cap hits
    python3 tools/mp4_asm_search.py "cmplwi" --with-c         # also show C source
    python3 tools/mp4_asm_search.py --rebuild-cache           # force re-disasm

First run takes ~2-3 minutes to disassemble all MP4 .o files into a flat
text cache (~100MB at /tmp/mp4_asm_cache.txt). Subsequent runs grep the
cache in <1s.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MP4_ROOT = REPO / "reference_projects" / "marioparty4"
MP4_OBJ_ROOT = MP4_ROOT / "build" / "GMPE01_00" / "obj"
MP4_SRC_ROOT = MP4_ROOT / "src"
MP4_EXTERN_ROOT = MP4_ROOT / "extern"
OBJDUMP = REPO / "build" / "binutils" / "powerpc-eabi-objdump"
CACHE = Path("/tmp/mp4_asm_cache.txt")


def build_cache():
    """Disassemble every MP4 .o into one flat text file with unit headers."""
    if not MP4_OBJ_ROOT.exists():
        sys.exit(f"MP4 not built: {MP4_OBJ_ROOT} missing. Run `cd reference_projects/marioparty4 && ninja` first.")
    if not OBJDUMP.exists():
        sys.exit(f"objdump not found at {OBJDUMP}. Run `ninja` in SFA-Decomp first to fetch binutils.")
    obj_files = sorted(MP4_OBJ_ROOT.rglob("*.o"))
    print(f"=== disassembling {len(obj_files)} MP4 object files into {CACHE} ===", file=sys.stderr)
    with open(CACHE, "w") as out:
        for i, obj in enumerate(obj_files, 1):
            if i % 50 == 0:
                print(f"  [{i}/{len(obj_files)}] {obj.name}", file=sys.stderr)
            rel = obj.relative_to(MP4_OBJ_ROOT)
            out.write(f"\n===== UNIT {rel} =====\n")
            try:
                disasm = subprocess.check_output(
                    [str(OBJDUMP), "-d", "-r", str(obj)],
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                ).decode("utf-8", errors="replace")
                out.write(disasm)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                out.write("# (objdump failed)\n")
    print(f"=== cache ready ({CACHE.stat().st_size // (1<<20)} MB) ===", file=sys.stderr)


def grep_cache(pattern, context):
    """Yield (unit, fn_name, asm_block_with_pattern) tuples."""
    pat = re.compile(pattern)
    current_unit = "?"
    current_fn = "?"
    fn_buffer = []
    hits_in_fn = []

    def flush_hits():
        for hit_line_idx in hits_in_fn:
            lo = max(0, hit_line_idx - context)
            hi = min(len(fn_buffer), hit_line_idx + context + 1)
            yield current_unit, current_fn, fn_buffer[lo:hi], fn_buffer[hit_line_idx]

    fn_re = re.compile(r"^[0-9a-f]+\s<(.+)>:")
    unit_re = re.compile(r"^===== UNIT (.+) =====")

    with open(CACHE) as f:
        for raw in f:
            line = raw.rstrip("\n")
            m_unit = unit_re.match(line)
            m_fn = fn_re.match(line)
            if m_unit:
                # flush previous fn before unit boundary
                if hits_in_fn:
                    yield from flush_hits()
                current_unit = m_unit.group(1)
                current_fn = "?"
                fn_buffer = []
                hits_in_fn = []
                continue
            if m_fn:
                # flush previous fn
                if hits_in_fn:
                    yield from flush_hits()
                current_fn = m_fn.group(1)
                fn_buffer = []
                hits_in_fn = []
                continue
            # accumulate this fn's lines
            idx = len(fn_buffer)
            fn_buffer.append(line)
            if pat.search(line):
                hits_in_fn.append(idx)
        # final flush
        if hits_in_fn:
            yield from flush_hits()


def find_c_source(fn_name):
    """grep MP4 src + extern for the function definition; return (path, snippet)."""
    # Strip C++ mangling decoration (everything after __ might still be the demangle)
    name = fn_name.split("__")[0] if "__" in fn_name and fn_name[0].isalpha() else fn_name
    for root in (MP4_SRC_ROOT, MP4_EXTERN_ROOT):
        if not root.exists():
            continue
        try:
            out = subprocess.check_output(
                ["grep", "-rln", "--include=*.c", "--include=*.cpp",
                 rf"\b{re.escape(name)}\s*(", str(root)],
                stderr=subprocess.DEVNULL,
            ).decode()
        except subprocess.CalledProcessError:
            continue
        for path in out.splitlines()[:1]:
            # read +20 lines of the definition
            try:
                src = open(path).read()
            except OSError:
                continue
            # find definition lines that look like a fn signature ending with `{`
            for m in re.finditer(
                rf"^[^/\n]*\b{re.escape(name)}\s*\([^;]*?\)\s*\{{",
                src, re.MULTILINE,
            ):
                start = m.start()
                # find balanced closing brace from `m.start()`
                depth = 0
                end = start
                in_str = False
                for i in range(m.end() - 1, len(src)):
                    ch = src[i]
                    if ch == '"' and src[i - 1] != "\\":
                        in_str = not in_str
                    if in_str:
                        continue
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                return Path(path).relative_to(MP4_ROOT), src[start:end]
    return None, None


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("pattern", nargs="?", help="regex matched against each asm line")
    p.add_argument("--context", "-C", type=int, default=4,
                   help="asm lines before/after each hit (default 4)")
    p.add_argument("--max", "-n", type=int, default=15, help="cap hits (default 15)")
    p.add_argument("--with-c", action="store_true",
                   help="also show the C source for each hit's containing fn")
    p.add_argument("--rebuild-cache", action="store_true",
                   help="re-disassemble MP4 .o files (slow, ~2-3 min)")
    p.add_argument("--unit-filter", default="",
                   help="only search MP4 units whose path contains this substring")
    args = p.parse_args()

    if args.rebuild_cache or not CACHE.exists():
        build_cache()
    if not args.pattern:
        sys.exit("Need a pattern. e.g. python3 tools/mp4_asm_search.py 'rlwimi'")

    seen_fns = set()
    hits = []
    for unit, fn, block, hit_line in grep_cache(args.pattern, args.context):
        if args.unit_filter and args.unit_filter not in unit:
            continue
        key = (unit, fn)
        if key in seen_fns:
            continue
        seen_fns.add(key)
        hits.append((unit, fn, block, hit_line))
        if len(hits) >= args.max:
            break

    print(f"=== {len(hits)} hit(s) for /{args.pattern}/ (unique fns) ===\n")
    for unit, fn, block, hit_line in hits:
        print(f"  MP4 unit: {unit}")
        print(f"  fn:        {fn}")
        print("  asm:")
        for line in block:
            marker = ">>>" if line == hit_line else "   "
            print(f"    {marker} {line.rstrip()}")
        if args.with_c:
            src_path, snippet = find_c_source(fn)
            if snippet:
                print(f"  C source: {src_path}")
                for ln in snippet.splitlines()[:30]:
                    print(f"    {ln}")
                if snippet.count("\n") > 30:
                    print("    ...")
            else:
                print(f"  C source: NOT FOUND for {fn}")
        print("-" * 78)


if __name__ == "__main__":
    main()
