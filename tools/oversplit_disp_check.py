#!/usr/bin/env python3
"""
Over-split discriminator (L75).

SOUND TEST, derived from voice_prio.o `voiceSetPriority` (a byte-exact fn):

  MWCC emits one R_PPC_ADDR16_HA/LO reloc pair per distinct file-scope object
  a function touches.  So in a function that matches retail BYTE-FOR-BYTE, if
  the code materializes symbol S and then does a load/store at S+disp with
  disp >= size(S), the RETAIL BYTES prove the real object extends past
  size(S) -- i.e. symbols.txt split one real aggregate into several names.

This adjudicates against retail bytes rather than against names, which is what
the over-split vein was missing.  Register provenance is tracked so that
displacements off unrelated pointers (parameters, loaded values) do not count.
"""
import json
import re
import subprocess
from collections import defaultdict

OBJDUMP = "build/binutils/powerpc-eabi-objdump"
SYMS = "config/GSAE01/symbols.txt"

sym_re = re.compile(
    r"^(\w+)\s*=\s*\.(\w+):0x([0-9A-Fa-f]+);.*?size:0x([0-9A-Fa-f]+)")
fn_re = re.compile(r"^[0-9a-f]{8} <([^>]+)>:")
insn_re = re.compile(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$")
reloc_re = re.compile(r"R_PPC_(\S+)\s+(\S+)")

MEM = {"lwz", "lwzu", "lhz", "lhzu", "lha", "lhau", "lbz", "lbzu",
       "stw", "stwu", "sth", "sthu", "stb", "stbu",
       "lfs", "lfsu", "lfd", "lfdu", "stfs", "stfsu", "stfd", "stfdu"}
STORES = {"stw", "stwu", "sth", "sthu", "stb", "stbu",
          "stfs", "stfsu", "stfd", "stfdu"}
# instrs that write rD = f(rA) and keep a base+offset relationship
UPDATE = {"lwzu", "lhzu", "lhau", "lbzu", "stwu", "sthu", "stbu",
          "lfsu", "lfdu", "stfsu", "stfdu"}

mem_operand_re = re.compile(r"(-?\d+)\(r(\d+)\)")
reg_re = re.compile(r"^r(\d+)$")


def load_syms():
    by_name, by_sect = {}, defaultdict(list)
    for line in open(SYMS):
        m = sym_re.match(line.strip())
        if m:
            name, sect, addr, size = m.groups()
            addr, size = int(addr, 16), int(size, 16)
            by_name[name] = (sect, addr, size)
            by_sect[sect].append((addr, size, name))
    for s in by_sect:
        by_sect[s].sort()
    return by_name, by_sect


def owner_of(by_sect, sect, addr):
    for a, sz, n in by_sect.get(sect, []):
        if a <= addr < a + sz:
            return n, addr - a
    return None, None


def units_at_100():
    d = json.load(open("build/GSAE01/report.json"))
    return [u["name"] for u in d["units"]
            if u["measures"]["fuzzy_match_percent"] >= 99.999999]


def obj_path(unit):
    parts = unit.split("/")
    if parts[0] == "main":
        parts = parts[1:]
    return "build/GSAE01/src/" + "/".join(parts) + ".o"


def scan_obj(path, by_name, by_sect):
    try:
        dis = subprocess.run([OBJDUMP, "-M", "gekko", "-drz", path],
                             capture_output=True, text=True,
                             timeout=120).stdout
    except Exception:
        return []

    findings = []
    cur_fn = None
    taint = {}          # reg -> (sym, offset)
    pending_ha = {}     # reg -> sym  (from lis ...@ha, awaiting the @lo)
    lines = dis.splitlines()

    for i, line in enumerate(lines):
        m = fn_re.match(line)
        if m:
            cur_fn = m.group(1)
            taint, pending_ha = {}, {}
            continue
        if not cur_fn:
            continue

        im = insn_re.match(line)
        if not im:
            continue
        op, args = im.group(1), im.group(2)
        # relocation for this insn, if any, sits on the following line
        rel = None
        if i + 1 < len(lines):
            r = reloc_re.search(lines[i + 1])
            if r:
                rel = r.groups()

        ops = [a.strip() for a in args.split(",")]

        # --- address materialization -------------------------------------
        if op == "lis" and rel and rel[0] == "ADDR16_HA":
            rm = reg_re.match(ops[0])
            if rm:
                pending_ha[int(rm.group(1))] = rel[1]
                taint.pop(int(rm.group(1)), None)
            continue

        if op in ("addi", "ori", "la") and rel and rel[0] == "ADDR16_LO":
            rd = reg_re.match(ops[0])
            ra = reg_re.match(ops[1]) if len(ops) > 1 else None
            if rd and ra and pending_ha.get(int(ra.group(1))) == rel[1]:
                taint[int(rd.group(1))] = (rel[1], 0)
            continue

        # a memory op with an @lo reloc: base is the pending-HA reg
        if op in MEM and rel and rel[0] == "ADDR16_LO":
            mo = mem_operand_re.search(args)
            if mo:
                ra = int(mo.group(2))
                if pending_ha.get(ra) == rel[1]:
                    pass  # direct symbol access at offset 0, nothing to flag
            rd = reg_re.match(ops[0])
            if rd and op not in STORES:
                taint.pop(int(rd.group(1)), None)
            continue

        # --- memory access off a tainted base ----------------------------
        if op in MEM:
            mo = mem_operand_re.search(args)
            if mo:
                disp, ra = int(mo.group(1)), int(mo.group(2))
                if ra in taint:
                    sym, off = taint[ra]
                    eff = off + disp
                    if sym in by_name:
                        sect, addr, size = by_name[sym]
                        if size and eff >= size:
                            own, rel_off = owner_of(by_sect, sect, addr + eff)
                            findings.append(
                                (cur_fn, sym, size, eff, own, rel_off))
                if op in UPDATE and ra in taint:
                    sym, off = taint[ra]
                    taint[ra] = (sym, off + disp)
            rd = reg_re.match(ops[0])
            if rd and op not in STORES:
                r = int(rd.group(1))
                if not (op in UPDATE and r == ra):
                    taint.pop(r, None)
            continue

        # --- pointer arithmetic that preserves provenance ----------------
        if op in ("addi", "addis") and len(ops) >= 3:
            rd, ra = reg_re.match(ops[0]), reg_re.match(ops[1])
            if rd and ra:
                d, a = int(rd.group(1)), int(ra.group(1))
                try:
                    imm = int(ops[2], 0)
                except ValueError:
                    imm = None
                if a in taint and imm is not None:
                    sym, off = taint[a]
                    taint[d] = (sym, off + (imm << 16 if op == "addis" else imm))
                    continue
            if rd:
                taint.pop(int(rd.group(1)), None)
            continue

        if op == "add" and len(ops) >= 3:
            rd, ra, rb = (reg_re.match(ops[0]), reg_re.match(ops[1]),
                          reg_re.match(ops[2]))
            if rd and ra and rb:
                d, a, b = (int(rd.group(1)), int(ra.group(1)),
                           int(rb.group(1)))
                ta, tb = taint.get(a), taint.get(b)
                # exactly one side tainted -> result keeps that provenance
                # (the other side is a runtime index, offset unknown-but->=0)
                if (ta is None) != (tb is None):
                    taint[d] = ta if ta is not None else tb
                    continue
            if rd:
                taint.pop(int(rd.group(1)), None)
            continue

        if op in ("mr", "mr."):
            rd, ra = reg_re.match(ops[0]), reg_re.match(ops[1])
            if rd and ra:
                d, a = int(rd.group(1)), int(ra.group(1))
                if a in taint:
                    taint[d] = taint[a]
                else:
                    taint.pop(d, None)
            continue

        if op.startswith("b"):
            # calls clobber volatiles
            if op in ("bl", "blrl", "bctrl"):
                for r in list(taint):
                    if r <= 12:
                        taint.pop(r, None)
                pending_ha.clear()
            continue

        # any other instruction: clear the destination register
        if ops:
            rd = reg_re.match(ops[0])
            if rd:
                taint.pop(int(rd.group(1)), None)

    return findings


def main():
    by_name, by_sect = load_syms()
    units = units_at_100()
    hits = defaultdict(list)
    total = 0
    for u in units:
        for fn, sym, size, eff, own, rel_off in scan_obj(
                obj_path(u), by_name, by_sect):
            hits[sym].append((u, fn, size, eff, own, rel_off))
            total += 1

    print(f"[units at 100%: {len(units)}] [findings: {total}] "
          f"[distinct over-split symbols: {len(hits)}]\n")
    for sym, rows in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        sect, addr, size = by_name[sym]
        partners = sorted({r[4] for r in rows if r[4]})
        best = max(r[3] for r in rows)
        print(f"### {sym}  .{sect}:0x{addr:08X}  declared 0x{size:X}  "
              f"-> byte-exact code reaches +0x{best:X}")
        print(f"      absorbs: {', '.join(partners) if partners else '(gap)'}")
        for u, fn, size, eff, own, rel_off in sorted(
                rows, key=lambda r: -r[3])[:3]:
            print(f"      {u}  {fn}  +0x{eff:X} -> {own}+0x{rel_off:X}"
                  if own else f"      {u}  {fn}  +0x{eff:X}")
        print()


if __name__ == "__main__":
    main()
