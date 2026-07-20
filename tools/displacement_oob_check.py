#!/usr/bin/env python3
"""Displacement out-of-bounds screen.

Usage:  displacement_oob_check.py {control|retail|src}

Run `control` first -- it builds a probe with a known in-bounds and a known
out-of-bounds access and asserts the screen fires on exactly one of them.

MWCC folds an array index into the INSTRUCTION displacement, not the reloc
addend (proved by control probe: `gSmall[64]` with sizeof gSmall == 4 emits
`li r3,gSmall@sda21` + `lbz r3,64(r3)` -- reloc addend 0).  So the sound
screen tracks the register that a relocation loads a symbol address into and
decodes every subsequent D-form access against it.

  lis  rX, sym@ha ; addi rX,rX,sym@l   -> rX = &sym
  li   rX, sym@sda21                   -> rX = &sym   (linker: addi rX,r13,..)
  <any D-form>  rD, K(rX)              -> access sym+K

K >= sizeof(sym) is an access past the declared end of the object.
A register is untracked as soon as anything else writes it.
"""
import re, subprocess, sys, json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OD = str(REPO / "build/binutils/powerpc-eabi-objdump")

SYMT = re.compile(r"^([0-9a-f]{8})\s+(.{7})\s+(\S+)\s+([0-9a-f]{8})\s+(\S+)$")
HDR = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INSN = re.compile(r"^\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\t(\S+)\s*(.*)$")
RELOC = re.compile(r"^\s*([0-9a-f]+): (R_PPC_\S+)\s+(\S+?)(?:\+0x([0-9a-f]+))?$")
DFORM = re.compile(r"^r?(\d+),(-?\d+)\((?:r)?(\d+)\)$")
FDFORM = re.compile(r"^f?(\d+),(-?\d+)\((?:r)?(\d+)\)$")

# D-form loads/stores only. Indexed (x-suffix) forms carry a runtime index and
# cannot be screened statically.
DFORM_OPS = {
    "lbz", "lbzu", "lha", "lhau", "lhz", "lhzu", "lwz", "lwzu", "lmw",
    "stb", "stbu", "sth", "sthu", "stw", "stwu", "stmw",
    "lfs", "lfsu", "lfd", "lfdu", "stfs", "stfsu", "stfd", "stfdu",
}


def sym_sizes(paths):
    out = {}
    for p in paths:
        r = subprocess.run([OD, "-t", str(p)], capture_output=True, text=True)
        for ln in r.stdout.splitlines():
            m = SYMT.match(ln.rstrip())
            if not m:
                continue
            _, flags, sec, size, name = m.groups()
            if sec in ("*UND*", "*ABS*") or "O" not in flags:
                continue
            sz = int(size, 16)
            if sz == 0:
                continue
            if name not in out or sz > out[name][0]:
                out[name] = (sz, sec, p.name)
    return out


def scan(obj, sizes):
    r = subprocess.run([OD, "-M", "gekko", "-drz", str(obj)],
                       capture_output=True, text=True)
    hits = []
    func = None
    track = {}          # reg -> (sym, addend)
    pending = None      # sym awaiting its @l  (reg, sym, addend)
    lastwrite = None    # register defined by the PRECEDING instruction; an
                        # objdump reloc line always follows its instruction
    lastop = None       # mnemonic of that preceding instruction
    for ln in r.stdout.splitlines():
        h = HDR.match(ln.strip())
        if h:
            func = h.group(2)
            track, pending = {}, None
            continue
        mr = RELOC.match(ln)
        if mr:
            _, typ, sym, add = mr.groups()
            add = int(add, 16) if add else 0
            # A reloc only yields an ADDRESS in a register when the host
            # instruction is address-forming.  On a load (`lwz rX,p@sda21(r13)`)
            # the register receives the pointer's VALUE, not its address --
            # treating that as a base was the screen's dominant false positive.
            addrform = lastop in ("li", "lis", "addi", "addis")
            if typ == "R_PPC_ADDR16_HA":
                pending = (sym, add)
            elif typ == "R_PPC_ADDR16_LO":
                if (pending and pending[0] == sym and lastwrite is not None
                        and addrform):
                    track[lastwrite] = (sym, add)
                pending = None
            elif typ == "R_PPC_EMB_SDA21":
                if lastwrite is not None and addrform:
                    track[lastwrite] = (sym, add)
                elif lastwrite is not None:
                    track.pop(lastwrite, None)
            continue
        mi = INSN.match(ln)
        if not mi:
            continue
        _, op, args = mi.groups()
        args = args.split("\t")[0].strip()
        base = op.rstrip(".")
        # Which register does this instruction define?  (first operand of the
        # ops we care about; loads define rD, stores define nothing.)
        lastwrite = None
        lastop = base
        m = re.match(r"^r?(\d+),", args)
        if m and not base.startswith("st"):
            lastwrite = int(m.group(1))
        if base in DFORM_OPS:
            m = DFORM.match(args) or FDFORM.match(args)
            if m:
                _, disp, rb = m.groups()
                rb, disp = int(rb), int(disp)
                if rb in track:
                    sym, add = track[rb]
                    off = add + disp
                    info = sizes.get(sym)
                    if info and off >= info[0]:
                        hits.append(dict(obj=obj.name, func=func, op=base,
                                         sym=sym, off=off, size=info[0],
                                         symsec=info[1], definer=info[2],
                                         onepast=(off == info[0])))
        # Untrack the defined register UNCONDITIONALLY.  Relocation lines are
        # emitted AFTER their instruction, so an address-forming reloc simply
        # re-establishes tracking on the following line.  Without this a plain
        # `lis rX,0xCC00` (hardware MMIO) left a stale symbol bound to rX and
        # every later MMIO displacement was reported as out of bounds.
        if lastwrite is not None:
            track.pop(lastwrite, None)
    return hits


def main():
    which = sys.argv[1]
    if which == "control":
        # Paired positive/negative control. Builds its own probe so the screen
        # can be re-validated after any toolchain or parser change.
        import tempfile, os
        d = Path(tempfile.mkdtemp())
        (d / "ctl.c").write_text(
            "unsigned char gSmall[4];\n"
            "unsigned char gBig[256];\n"
            "int inbounds(void) { return gBig[8] + gSmall[2]; }\n"
            "int oob(void)      { return gSmall[64]; }\n")
        cc = [str(REPO / "build/tools/wibo"),
              str(REPO / "build/compilers/GC/2.0/mwcceppc.exe"), "-c",
              "-nodefaults", "-proc", "gekko", "-align", "powerpc", "-O4,p",
              "-nosyspath", "-o", str(d / "ctl.o"), str(d / "ctl.c")]
        if subprocess.run(cc, capture_output=True).returncode != 0:
            print("control: FAILED TO BUILD PROBE")
            return
        hits = scan(d / "ctl.o", sym_sizes([d / "ctl.o"]))
        ok = (len(hits) == 1 and hits[0]["func"] == "oob"
              and hits[0]["sym"] == "gSmall" and hits[0]["off"] == 64)
        print("control: POSITIVE (gSmall[64] vs size 4) and NEGATIVE "
              "(gBig[8], gSmall[2]) -> " + ("PASS" if ok else "FAIL"))
        for h in hits:
            print("  hit:", h["func"], h["sym"], hex(h["off"]), "size", h["size"])
        return
    root = REPO / ("build/GSAE01/obj" if which == "retail"
                   else "build/GSAE01/src")
    paths = sorted(root.rglob("*.o"))
    universe = (sorted((REPO / "build/GSAE01/obj").rglob("*.o")) +
                sorted((REPO / "build/GSAE01/src").rglob("*.o")))
    sizes = sym_sizes(universe)
    hits = []
    for p in paths:
        hits.extend(scan(p, sizes))
    strong = [h for h in hits if not h["onepast"]]
    print(f"{which}: objects={len(paths)} syms={len(sizes)} "
          f"hits={len(hits)} strong={len(strong)}")
    (REPO / f"scratchpad/L135_disp_{which}.json").write_text(
        json.dumps(hits, indent=1))
    for h in strong[:60]:
        print(f"  {h['obj']:40s} {h['func']:34s} {h['op']:5s} "
              f"{h['sym']}+0x{h['off']:x} size=0x{h['size']:x} ({h['symsec']})")


main()
