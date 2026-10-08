#!/usr/bin/env python3
"""Remove unreferenced local functions from an MWCC object, the way the linker's dead-strip does.

MWCC still emits an out-of-line copy of a static function even when every call to it was
inlined. The final link strips that copy together with its extab/extabindex entries, so the
retail-derived target object never has them. Comparing the raw compiled object against that
target counts the leftover exception-table entries as a data mismatch even though the linked
DOL is identical. This rewrites the object in place without them.

    python3 tools/dead_strip_object.py build/GSAE01/src/musyx/runtime/sal_volume.o
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

SHT_SYMTAB = 2
SHT_RELA = 4
STT_FUNC = 2
STB_LOCAL = 0
EXTAB_ENTRY = 8
EXTABINDEX_ENTRY = 12
COMMENT_HEADER = 0x2C
COMMENT_ENTRY = 8


class Section:
    def __init__(self, raw: bytes, data: bytes) -> None:
        (self.name, self.type, self.flags, self.addr, self.offset, self.size,
         self.link, self.info, self.addralign, self.entsize) = struct.unpack(">10I", raw)
        self.data = bytearray(data)


def section_name(sections: list[Section], shstrndx: int, sec: Section) -> str:
    table = sections[shstrndx].data
    end = table.index(b"\0", sec.name)
    return table[sec.name:end].decode()


def read_symbols(sec: Section) -> list[list[int]]:
    return [list(struct.unpack_from(">IIIBBH", sec.data, i)) for i in range(0, len(sec.data), 16)]


def read_relocs(sec: Section) -> list[list[int]]:
    return [list(struct.unpack_from(">IIi", sec.data, i)) for i in range(0, len(sec.data), 12)]


def cut(data: bytearray, ranges: list[tuple[int, int]]) -> bytearray:
    out = bytearray()
    pos = 0
    for start, end in sorted(ranges):
        out += data[pos:start]
        pos = end
    out += data[pos:]
    return out


def shift(offset: int, ranges: list[tuple[int, int]]) -> int:
    return offset - sum(end - start for start, end in ranges if end <= offset)


def inside(offset: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in ranges)


def main() -> None:
    path = Path(sys.argv[1])
    blob = path.read_bytes()
    header = bytearray(blob[:52])
    shoff, = struct.unpack_from(">I", header, 0x20)
    shnum, shstrndx = struct.unpack_from(">HH", header, 0x30)
    sections = []
    for i in range(shnum):
        raw = blob[shoff + i * 40:shoff + (i + 1) * 40]
        sec = Section(raw, b"")
        sec.data = bytearray(blob[sec.offset:sec.offset + sec.size]) if sec.type != 8 else bytearray()
        sections.append(sec)
    names = [section_name(sections, shstrndx, s) for s in sections]
    symtab_index = next(i for i, s in enumerate(sections) if s.type == SHT_SYMTAB)
    symtab = sections[symtab_index]
    symbols = read_symbols(symtab)
    relocs = {i: read_relocs(s) for i, s in enumerate(sections) if s.type == SHT_RELA}
    extab = names.index("extab") if "extab" in names else None
    extabindex = names.index("extabindex") if "extabindex" in names else None

    referenced = set()
    for i, rels in relocs.items():
        if sections[i].info == extabindex:
            continue
        for _, info, _ in rels:
            referenced.add(info >> 8)

    dead = [n for n, (_, value, size, info, _, shndx) in enumerate(symbols)
            if info & 0xF == STT_FUNC and info >> 4 == STB_LOCAL and n not in referenced and size > 0]
    if not dead:
        return

    removed: dict[int, list[tuple[int, int]]] = {}
    for n in dead:
        _, value, size, _, _, shndx = symbols[n]
        removed.setdefault(shndx, []).append((value, value + size))
    if extabindex is not None:
        index_relocs = next(rels for i, rels in relocs.items() if sections[i].info == extabindex)
        by_offset = {off: info >> 8 for off, info, _ in index_relocs}
        for entry in range(0, len(sections[extabindex].data), EXTABINDEX_ENTRY):
            if by_offset.get(entry) in dead:
                removed.setdefault(extabindex, []).append((entry, entry + EXTABINDEX_ENTRY))
                table_sym = by_offset[entry + 8]
                start = symbols[table_sym][1]
                removed.setdefault(extab, []).append((start, start + EXTAB_ENTRY))

    keep = [n for n, (_, value, _, _, _, shndx) in enumerate(symbols)
            if n == 0 or not (shndx in removed and inside(value, removed[shndx])
                              and symbols[n][3] & 0xF != 3)]
    new_index = {old: new for new, old in enumerate(keep)}

    for i, rels in relocs.items():
        target = sections[i].info
        ranges = removed.get(target, [])
        kept = []
        for off, info, addend in rels:
            if inside(off, ranges):
                continue
            sym = info >> 8
            sym_shndx = symbols[sym][5]
            if symbols[sym][3] & 0xF == 3 and sym_shndx in removed:
                addend = shift(addend, removed[sym_shndx])
            kept.append((shift(off, ranges), (new_index[sym] << 8) | (info & 0xFF), addend))
        sections[i].data = bytearray(b"".join(struct.pack(">IIi", *r) for r in kept))

    new_symbols = []
    for n in keep:
        name, value, size, info, other, shndx = symbols[n]
        if shndx in removed and info & 0xF != 3:
            value = shift(value, removed[shndx])
        new_symbols.append(struct.pack(">IIIBBH", name, value, size, info, other, shndx))
    symtab.data = bytearray(b"".join(new_symbols))
    symtab.info = sum(1 for n in keep if symbols[n][3] >> 4 == STB_LOCAL)

    if ".comment" in names:
        comment = sections[names.index(".comment")]
        body = comment.data
        entries = [body[COMMENT_HEADER + n * COMMENT_ENTRY:COMMENT_HEADER + (n + 1) * COMMENT_ENTRY]
                   for n in range(len(symbols))]
        comment.data = bytearray(body[:COMMENT_HEADER] + b"".join(entries[n] for n in keep))

    for shndx, ranges in removed.items():
        sections[shndx].data = cut(sections[shndx].data, ranges)

    out = bytearray(header)
    for sec in sections[1:]:
        align = max(sec.addralign, 1)
        if sec.type != 8:
            out += b"\0" * (-len(out) % align)
            sec.offset = len(out)
            out += sec.data
        sec.size = len(sec.data) if sec.type != 8 else sec.size
    out += b"\0" * (-len(out) % 4)
    struct.pack_into(">I", out, 0x20, len(out))
    for sec in sections:
        out += struct.pack(">10I", sec.name, sec.type, sec.flags, sec.addr, sec.offset, sec.size,
                           sec.link, sec.info, sec.addralign, sec.entsize)
    path.write_bytes(bytes(out))


if __name__ == "__main__":
    main()
