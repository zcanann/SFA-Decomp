#!/usr/bin/env python3
"""SDA21 / pool reloc-TARGET correctness detector.

fuzzy_match_percent does NOT compare relocation TARGETS: a function can score
100.0 while loading the WRONG constant (duster's mutatedEbaInit loaded
baddieInit's 40.0/0.02/0.1 instead of its own 60.0/0.01/0.006).

Method
  1. Match functions by NAME (file offsets differ between our .o and retail .o).
  2. Normalize: zero the immediate of every relocated instruction. If normalized
     bytes are EQUAL the two functions have identical instruction ENCODINGS, so
     every remaining difference lives purely in the reloc targets -- exactly the
     class fuzzy is blind to.
  3. Resolve each target to its VALUE BYTES:
       - symbol DEFINED in the object -> read that object's own section data,
         indexed by st_shndx (objects may hold several same-named sections).
       - UND symbol -> resolve by address (lbl_ADDR name, or the retail symbol
         map) and read from the retail image / main.dol.
     Equal value  -> the documented legit anon-@NNN vs named-lbl_ pairing.
     Different value / address -> BUG.

Usage: python3 tools/sda_reloc_check.py [out.json]
"""
import json, os, re, struct, sys


# --- minimal ELF32-BE reader ---
# Minimal big-endian ELF32 reader for PPC objects.
# 
# Needed because objdump's textual output is ambiguous: these objects can contain
# SEVERAL sections with the SAME NAME (e.g. two `.sdata2` in a DLL obj), so any
# name-keyed map silently reads the wrong section's bytes. Symbols carry st_shndx,
# so only real section INDICES disambiguate them.
import struct

SHT_SYMTAB, SHT_RELA, SHT_REL, SHT_NOBITS = 2, 4, 9, 8


class Elf:
    def __init__(self, path):
        d = open(path, "rb").read()
        self.d = d
        assert d[:4] == b"\x7fELF" and d[5] == 2, path      # ELF32 big-endian
        (self.e_shoff,) = struct.unpack_from(">I", d, 0x20)
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from(">HHH", d, 0x2E)
        self.sh = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            name, typ, flags, addr, off, size, link, info, align, entsz = \
                struct.unpack_from(">10I", d, o)
            self.sh.append(dict(name_off=name, type=typ, flags=flags, addr=addr,
                                offset=off, size=size, link=link, info=info))
        shstr = self.sh[self.e_shstrndx]
        self._shstr = d[shstr["offset"]:shstr["offset"] + shstr["size"]]
        for s in self.sh:
            s["name"] = self._str(self._shstr, s["name_off"])

    @staticmethod
    def _str(tab, off):
        e = tab.find(b"\0", off)
        return tab[off:e].decode("utf-8", "replace")

    def sec_data(self, i):
        s = self.sh[i]
        if s["type"] == SHT_NOBITS:
            return b""
        return self.d[s["offset"]:s["offset"] + s["size"]]

    def symbols(self):
        """[(name, shndx, value, size, bind)] in symtab order"""
        out = []
        for i, s in enumerate(self.sh):
            if s["type"] != SHT_SYMTAB:
                continue
            strtab = self.d[self.sh[s["link"]]["offset"]:
                            self.sh[s["link"]]["offset"] + self.sh[s["link"]]["size"]]
            n = s["size"] // 16
            for j in range(n):
                o = s["offset"] + j * 16
                nm, val, sz, info, other, shndx = struct.unpack_from(">IIIBBH", self.d, o)
                out.append((self._str(strtab, nm), shndx, val, sz, info >> 4))
        return out

    def relocs(self, target_sec_idx):
        """[(offset, type, sym_index, addend)] for relocs applying to a section"""
        out = []
        for s in self.sh:
            if s["type"] not in (SHT_REL, SHT_RELA) or s["info"] != target_sec_idx:
                continue
            esz = 12 if s["type"] == SHT_RELA else 8
            for o in range(s["offset"], s["offset"] + s["size"], esz):
                if s["type"] == SHT_RELA:
                    off, info, add = struct.unpack_from(">IIi", self.d, o)
                else:
                    off, info = struct.unpack_from(">II", self.d, o)
                    add = 0
                out.append((off, info & 0xFF, info >> 8, add))
        return out

    def sec_index(self, name):
        for i, s in enumerate(self.sh):
            if s["name"] == name:
                return i
        return None


ROOT = "/Users/zcanann/Documents/Projects/SFA-Decomp"
OBJDIR = os.path.join(ROOT, "build/GSAE01/obj")
# Ghidra-import names encode the address they were lifted from: lbl_803DEA04,
# DAT_803dd8bd, D_8035F680. Used only for UND symbols (a locally DEFINED symbol
# may carry such a name while living somewhere else entirely -- see msgbuf.c).
LBL_RE = re.compile(r"^(?:lbl|DAT|dat|D|d)_([0-9A-Fa-f]{8})$")
ANON_RE = re.compile(r"^@\d+$")

R_SDA21, R_ADDR16_HA, R_ADDR16_LO, R_ADDR16, R_REL24 = 109, 5, 4, 3, 10
IMM16 = {R_SDA21, R_ADDR16_HA, R_ADDR16_LO, R_ADDR16, 6, 7}


def dol_spans():
    d = open(os.path.join(ROOT, "build/GSAE01/main.dol"), "rb").read()
    offs = struct.unpack(">18I", d[0x00:0x48])
    addrs = struct.unpack(">18I", d[0x48:0x90])
    sizes = struct.unpack(">18I", d[0x90:0xD8])
    return sorted((a, d[o:o + s]) for o, a, s in zip(offs, addrs, sizes) if s and a)


DOL = dol_spans()


def dol_read(addr, n):
    for base, data in DOL:
        if base <= addr and addr + n <= base + len(data):
            return data[addr - base:addr - base + n]
    return None


class Obj:
    def __init__(self, path):
        self.e = Elf(os.path.join(ROOT, path) if not path.startswith("/") else path)
        self.syms = self.e.symbols()
        self.text_i = self.e.sec_index(".text")

    def fns(self):
        out = {}
        for nm, shndx, val, sz, bind in self.syms:
            if shndx == self.text_i and sz and nm:
                out[nm] = (val, sz)
        return out

    def text(self):
        return self.e.sec_data(self.text_i) if self.text_i is not None else b""

    def text_relocs(self):
        """[(offset, type, symname, addend, defined_here, value_reader)]"""
        out = []
        for off, typ, si, add in self.e.relocs(self.text_i):
            nm, shndx, val, sz, bind = self.syms[si]
            out.append((off, typ, nm, add, shndx, val, sz))
        return sorted(out)

    def reloc_offsets(self, shndx):
        if not hasattr(self, "_ro"):
            self._ro = {}
        if shndx not in self._ro:
            self._ro[shndx] = {o for o, t, s, a in self.e.relocs(shndx)}
        return self._ro[shndx]

    def has_reloc(self, shndx, off, n):
        """True if [off, off+n) inside section shndx is itself relocated."""
        rs = self.reloc_offsets(shndx)
        return any(off <= r < off + n for r in rs)

    def value_of(self, shndx, val, add, n):
        """Value of a symbol DEFINED in this object (shndx is a real section)."""
        if shndx == 0 or shndx >= 0xFF00:
            return None
        if self.e.sh[shndx]["type"] == SHT_NOBITS:
            return None
        d = self.e.sec_data(shndx)
        o = val + add
        return d[o:o + n] if o + n <= len(d) else None


def load_retail_addrs():
    """symbol -> address, from the authoritative retail symbol map.

    symbols.txt covers every symbol (including those inside carved unit objs),
    unlike the auto_*.o data objects alone. Names that map to SEVERAL addresses
    are ambiguous (e.g. Gwid/Gbase/__THPInfo each name both a real THP .sbss
    variable and a mis-named .sdata2 float constant) -> drop them rather than
    guess, so ambiguity can never manufacture a finding.
    """
    m, dup = {}, set()
    path = os.path.join(ROOT, "config/GSAE01/symbols.txt")
    for line in open(path):
        g = re.match(r"^(\S+) = \.(\w+):0x([0-9A-Fa-f]{8});", line)
        if not g:
            continue
        nm, addr = g.group(1), int(g.group(3), 16)
        if nm in m and m[nm] != addr:
            dup.add(nm)
        m[nm] = addr
    for nm in dup:
        m.pop(nm, None)
    sys.stderr.write(f"[symbols.txt: {len(m)} unique, {len(dup)} ambiguous dropped]\n")
    return m


def fmt(b):
    if b is None:
        return "?"
    if len(b) == 4:
        return f"f32 {struct.unpack('>f', b)[0]:g} (0x{struct.unpack('>I', b)[0]:08x})"
    if len(b) == 8:
        return f"f64 {struct.unpack('>d', b)[0]:g}"
    return b.hex()[:24]


def normalize(text, rels, start, size):
    b = bytearray(text[start:start + size])
    for off, typ, nm, add, shndx, val, sz in rels:
        if not (start <= off < start + size):
            continue
        i = off - start
        if typ in IMM16 and i + 2 <= len(b):
            b[i:i + 2] = b"\0\0"
        elif typ == R_REL24:
            j = i - (i % 4)
            if j + 4 <= len(b):
                w = struct.unpack_from(">I", b, j)[0]
                struct.pack_into(">I", b, j, w & 0xFC000003)
    return bytes(b)


def main():
    RA = load_retail_addrs()
    sys.stderr.write(f"[retail symbol addrs: {len(RA)}]\n")
    units = [u for u in json.load(open(os.path.join(ROOT, "objdiff.json")))["units"]
             if "base_path" in u and "target_path" in u]
    rep = json.load(open(os.path.join(ROOT, "build/GSAE01/report.json")))
    pct = {u["name"]: u["measures"].get("fuzzy_match_percent", 0) for u in rep["units"]}

    findings, checked = [], 0
    for u in units:
        po, pr = u["base_path"], u["target_path"]
        if not (os.path.exists(os.path.join(ROOT, po)) and os.path.exists(os.path.join(ROOT, pr))):
            continue
        try:
            O, T = Obj(po), Obj(pr)
        except Exception as ex:
            sys.stderr.write(f"[skip {u['name']}: {ex}]\n")
            continue
        if O.text_i is None or T.text_i is None:
            continue
        to, tt = O.text(), T.text()
        ro, rt = O.text_relocs(), T.text_relocs()
        fo, ft = O.fns(), T.fns()
        for name in sorted(set(fo) & set(ft)):
            (so, szo), (sr, szr) = fo[name], ft[name]
            if szo != szr or normalize(to, ro, so, szo) != normalize(tt, rt, sr, szr):
                continue
            checked += 1
            lo = [(x[0] - so,) + tuple(x[1:]) for x in ro if so <= x[0] < so + szo]
            lt = [(x[0] - sr,) + tuple(x[1:]) for x in rt if sr <= x[0] < sr + szr]
            if [x[0] for x in lo] != [x[0] for x in lt]:
                continue
            for a, b in zip(lo, lt):
                d, t1, n1, ad1, sx1, v1v, sz1 = a
                _, t2, n2, ad2, sx2, v2v, sz2 = b
                if n1 == n2 and ad1 == ad2:
                    continue
                if t1 not in IMM16:
                    continue
                # A datum that itself carries relocations (switch jump tables,
                # pointer arrays) is never value-comparable: our pre-link copy
                # holds zeros exactly where retail's carved copy holds resolved
                # addresses. Covers `jumptable_*` and anon `@NNN` tables alike.
                n = sz1 if sz1 in (1, 2, 4, 8) else 4
                if n1.startswith("jumptable_") or n2.startswith("jumptable_"):
                    continue
                if sx1 and sx1 < 0xFF00 and O.has_reloc(sx1, v1v + ad1, n):
                    continue

                # --- ours: our object is UNLINKED, so only an UND symbol has a
                # knowable address. A symbol DEFINED here (@NNN, or msgbuf.c's
                # own `const char lbl_802C30D8[]`) must be read locally: its
                # name may encode an address that is NOT where it really lives.
                if sx1 and sx1 < 0xFF00:
                    val1, addr1 = O.value_of(sx1, v1v, ad1, n), None
                else:
                    addr1 = RA.get(n1)
                    if addr1 is None:
                        g = LBL_RE.match(n1)
                        addr1 = int(g.group(1), 16) if g else None
                    addr1 = addr1 + ad1 if addr1 is not None else None
                    val1 = dol_read(addr1, n) if addr1 is not None else None

                # --- retail: carved from the fixed image, so EVERY symbol has a
                # real address -- resolve by name even when defined locally.
                addr2 = RA.get(n2)
                if addr2 is None:
                    g = LBL_RE.match(n2)
                    addr2 = int(g.group(1), 16) if g else None
                addr2 = addr2 + ad2 if addr2 is not None else None
                val2 = dol_read(addr2, n) if addr2 is not None else None
                if val2 is None and sx2 and sx2 < 0xFF00:
                    val2 = T.value_of(sx2, v2v, ad2, n)

                if addr1 is not None and addr2 is not None:
                    if addr1 == addr2:
                        continue
                    kind = "wrong-address"
                elif val1 is not None and val2 is not None:
                    if val1 == val2:
                        continue
                    kind = "wrong-value"
                else:
                    continue
                findings.append(dict(unit=u["name"], pct=pct.get(u["name"], 0), fn=name,
                                     delta=d, kind=kind, size=n,
                                     ours=n1, ours_val=fmt(val1),
                                     retail=n2, retail_val=fmt(val2)))
    out = sys.argv[1] if len(sys.argv) > 1 else "/dev/stdout"
    json.dump(findings, open(out, "w"), indent=1)
    sys.stderr.write(f"[encoding-identical fns checked: {checked}] [findings: {len(findings)}]\n")


if __name__ == "__main__":
    main()
