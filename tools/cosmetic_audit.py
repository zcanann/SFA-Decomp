#!/usr/bin/env python3
"""Audit "cosmetic" 99.9%+ functions for real (non-reloc) byte differences.

A function scoring <100% but visually identical via `function_objdump.py --diff`
is usually one of:
  (a) Pure reloc-target difference (symbol@HI/LO bytes the diff tolerates) —
      genuinely cosmetic, can't be fixed via source.
  (b) ONE-to-FEW literal-operand bytes differ (loop counts, displacement
      literals, immediates) — a REAL behavioral or instruction-selection
      difference disguised as a pool-name artifact. Worth fixing.

This tool scans every fn ≥ min_pct, extracts the raw .text bytes for the
symbol from both target and current .o files, computes a relocation-aware
mask (zeroes out the bits each reloc affects), and reports only functions
whose remaining diff is non-empty after masking.

Usage:
    python3 tools/cosmetic_audit.py                       # default ≥99.9%, ≤500B
    python3 tools/cosmetic_audit.py --min-pct 99.5
    python3 tools/cosmetic_audit.py --max-size 1000
    python3 tools/cosmetic_audit.py --unit-filter newshadows
"""
import argparse
import json
import struct
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OBJDUMP = REPO / "build" / "binutils" / "powerpc-eabi-objdump"


# PowerPC reloc types and the byte ranges they patch (within the 4-byte
# instruction at the reloc offset). objdump shows the offset of the FIRST
# byte the linker patches; for our purposes any difference in the patched
# bytes is reloc noise.
RELOC_INSTR_BYTES = {
    "R_PPC_ADDR16_HA": (2, 4),   # patches lower halfword (bytes 2..3 of a 4B instr)
    "R_PPC_ADDR16_LO": (2, 4),
    "R_PPC_ADDR16_HI": (2, 4),
    "R_PPC_ADDR16": (2, 4),
    "R_PPC_EMB_SDA21": (0, 4),   # patches all 4 bytes (rA + 16-bit displacement)
    "R_PPC_REL24": (0, 4),       # patches 4 bytes (bl/branch target encoded across)
    "R_PPC_REL14": (0, 4),
}


def get_section_info(objfile, name):
    """Return (file_offset, vma) for a section."""
    out = subprocess.check_output([str(OBJDUMP), "-h", str(objfile)]).decode()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 7 and parts[1] == name:
            return int(parts[5], 16), int(parts[3], 16)
    return None, None


def get_symbols(objfile):
    """Return {name: (addr, size)} for .text symbols."""
    out = subprocess.check_output([str(OBJDUMP), "-t", str(objfile)]).decode()
    syms = {}
    for line in out.splitlines():
        # e.g. "00004da4 g     F .text	0000016c objAudioFn_8006edcc"
        if " F .text" not in line:
            continue
        parts = line.split()
        try:
            addr = int(parts[0], 16)
            # find size — column right after .text
            tx_idx = parts.index(".text")
            size = int(parts[tx_idx + 1], 16)
            name = parts[-1]
            syms[name] = (addr, size)
        except (ValueError, IndexError):
            pass
    return syms


def get_relocs_in_text(objfile, lo, hi):
    """Return list of (offset, reloc_type) for relocs in [lo, hi) of .text."""
    try:
        out = subprocess.check_output(
            ["objdump", "-r", "-j", ".text", str(objfile)]
        ).decode()
    except subprocess.CalledProcessError:
        return []
    relocs = []
    for line in out.splitlines():
        # e.g. "00004dbc R_PPC_REL24       _savegpr_27"
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            off = int(parts[0], 16)
            rtype = parts[1]
            if rtype in RELOC_INSTR_BYTES and lo <= off < hi:
                relocs.append((off, rtype))
        except ValueError:
            pass
    return relocs


def read_fn_bytes(objfile, sym_addr, sym_size, text_offset):
    with open(objfile, "rb") as f:
        f.seek(text_offset + sym_addr)
        return bytearray(f.read(sym_size))


def mask_relocs(buf, relocs, sym_addr):
    """Zero out byte ranges covered by relocs."""
    for off, rtype in relocs:
        lo, hi = RELOC_INSTR_BYTES[rtype]
        instr_off = (off - sym_addr) & ~3
        for b in range(instr_off + lo, instr_off + hi):
            if 0 <= b < len(buf):
                buf[b] = 0


def disasm_instr(objfile, sym_addr, instr_off):
    """One-line disassembly for the instruction at sym_addr+instr_off."""
    try:
        out = subprocess.check_output(
            [str(OBJDUMP), "-d", "--start-address", hex(sym_addr + instr_off),
             "--stop-address", hex(sym_addr + instr_off + 4), str(objfile)],
            stderr=subprocess.DEVNULL,
        ).decode()
        for line in out.splitlines():
            # match e.g. "    4df4:\t38 00 00 08 \tli      r0,8"
            ls = line.lstrip()
            if ":\t" in ls and not ls.startswith("Disassembly"):
                return ls.split(":\t", 1)[1].strip()
    except subprocess.CalledProcessError:
        pass
    return "<?>"


def audit_function(tgt_obj, cur_obj, name, tgt_info, cur_info,
                   tgt_text_off, cur_text_off):
    """Returns dict with diff info, or None if byte-identical-modulo-relocs."""
    tgt_addr, tgt_size = tgt_info
    cur_addr, cur_size = cur_info
    if tgt_size != cur_size:
        return {"size_mismatch": (tgt_size, cur_size)}
    buf_t = read_fn_bytes(tgt_obj, tgt_addr, tgt_size, tgt_text_off)
    buf_c = read_fn_bytes(cur_obj, cur_addr, cur_size, cur_text_off)
    if buf_t == buf_c:
        return None
    relocs_t = get_relocs_in_text(tgt_obj, tgt_addr, tgt_addr + tgt_size)
    relocs_c = get_relocs_in_text(cur_obj, cur_addr, cur_addr + cur_size)
    mask_relocs(buf_t, relocs_t, tgt_addr)
    mask_relocs(buf_c, relocs_c, cur_addr)
    if buf_t == buf_c:
        return None  # purely reloc-byte diffs — cosmetic
    diffs = []
    for i, (t, c) in enumerate(zip(buf_t, buf_c)):
        if t != c:
            diffs.append((i, t, c))
    # cluster by instruction
    instr_diffs = {}
    for off, t, c in diffs:
        instr_off = off & ~3
        instr_diffs.setdefault(instr_off, []).append((off & 3, t, c))
    return {
        "n_diff_bytes": len(diffs),
        "n_diff_instrs": len(instr_diffs),
        "diffs": [
            (
                instr_off,
                disasm_instr(tgt_obj, tgt_addr, instr_off),
                disasm_instr(cur_obj, cur_addr, instr_off),
                instr_diffs[instr_off],
            )
            for instr_off in sorted(instr_diffs)
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-pct", type=float, default=99.9)
    ap.add_argument("--max-pct", type=float, default=100.0)
    ap.add_argument("--max-size", type=int, default=500)
    ap.add_argument("--unit-filter", default="")
    ap.add_argument("--show-cosmetic", action="store_true",
                    help="also report functions that ARE purely cosmetic")
    args = ap.parse_args()

    report = REPO / "build" / "GSAE01" / "report.json"
    with open(report) as f:
        r = json.load(f)

    candidates = []
    for u in r.get("units", []):
        name = u.get("name", "")
        if "placeholder" in name:
            continue
        if args.unit_filter and args.unit_filter not in name:
            continue
        for fn in u.get("functions", []):
            fp = float(fn.get("fuzzy_match_percent", 0))
            sz = int(fn.get("size", 0))
            if args.min_pct <= fp < args.max_pct and sz <= args.max_size:
                candidates.append((fp, sz, name, fn.get("name", "?")))
    candidates.sort()
    print(f"=== auditing {len(candidates)} candidates "
          f"({args.min_pct}% ≤ fuzzy < {args.max_pct}%, size ≤ {args.max_size}B) ===\n")

    real_bugs = []
    pure_cosmetic = 0
    errors = 0
    for fp, sz, unit, fn_name in candidates:
        u_short = unit.replace("main/main/", "").replace("main/", "")
        # construct .o paths from unit
        # unit names like "main/main/newshadows" -> "build/GSAE01/obj/main/newshadows.o"
        # strip the OUTER "main/" prefix (the build directory disambiguator)
        relpath = unit[5:] if unit.startswith("main/") else unit
        tgt_obj = (REPO / "build" / "GSAE01" / "obj" / relpath).with_suffix(".o")
        cur_obj = (REPO / "build" / "GSAE01" / "src" / relpath).with_suffix(".o")
        if not tgt_obj.exists() or not cur_obj.exists():
            errors += 1
            continue
        tgt_text_off, _ = get_section_info(tgt_obj, ".text")
        cur_text_off, _ = get_section_info(cur_obj, ".text")
        tgt_syms = get_symbols(tgt_obj)
        cur_syms = get_symbols(cur_obj)
        if fn_name not in tgt_syms or fn_name not in cur_syms:
            errors += 1
            continue
        result = audit_function(tgt_obj, cur_obj, fn_name, tgt_syms[fn_name],
                                cur_syms[fn_name], tgt_text_off, cur_text_off)
        if result is None:
            pure_cosmetic += 1
            if args.show_cosmetic:
                print(f"  COSMETIC: {fp:.4f}% {sz:>4}B  {u_short}/{fn_name}")
            continue
        if "size_mismatch" in result:
            print(f"  SIZE-MISMATCH: {u_short}/{fn_name}  T={result['size_mismatch'][0]} C={result['size_mismatch'][1]}")
            continue
        real_bugs.append((fp, sz, u_short, fn_name, result))

    print(f"=== REAL BUGS: {len(real_bugs)} | PURE COSMETIC: {pure_cosmetic} | ERRORS: {errors} ===\n")
    for fp, sz, u, fn, result in real_bugs[:40]:
        print(f"  {fp:7.4f}%  {sz:>4}B  {u}/{fn}")
        print(f"    {result['n_diff_bytes']} byte(s) in {result['n_diff_instrs']} instr(s)")
        for instr_off, t_disasm, c_disasm, byte_diffs in result["diffs"][:3]:
            print(f"    @ +{instr_off:#06x}:  T: {t_disasm}")
            print(f"                  C: {c_disasm}")


if __name__ == "__main__":
    main()
