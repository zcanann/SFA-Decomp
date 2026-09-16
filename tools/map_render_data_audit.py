#!/usr/bin/env python3
"""Audit the EN map-rendering TU's recovered data independently of fuzzy matching.

Run after `ninja all_source`. This checks allocated data, native symbol offsets,
jump-table destinations, and direct retail pool loads. It does not certify text
matching or replace the strict source-linked DOL checksum.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

from pool_content_check import parse_splits
from tricky_object_compare import read_object


ROOT = Path(__file__).resolve().parent.parent
UNIT = "main/shader.c"


ZERO_COLOR_TEMPLATES = {
    "sGlowFogColor": ("renderGlows", 0x1C, 0),
    "gTexShaderFogColor": ("mapBlockRender_setShader", 0x10, 4),
    "gTexLightmapFogColor": ("mapBlockRender_setLightmapShader", 0x10, 8),
}


def audit_zero_colors(snapshot, source: Path) -> None:
    """Match anonymous GXColor templates by their complete layout and live loads."""
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_index(".sbss2")
        layouts = sorted(
            (symbol["st_value"], symbol["st_size"])
            for symbol in elf.get_section_by_name(".symtab").iter_symbols()
            if symbol["st_shndx"] == section and symbol["st_info"]["type"] == "STT_OBJECT"
        )
    assert layouts == [(0, 4), (4, 4), (8, 4)], "zero-color template layout differs"

    expected = []
    for function, offset, template in ZERO_COLOR_TEMPLATES.values():
        symbol = snapshot.symbols[function]
        assert symbol[0] == ".text" and offset + 4 <= symbol[2]
        expected.append((symbol[1] + offset, 109, 0, template))  # R_PPC_EMB_SDA21
    actual = []
    for section, records in snapshot.relocations.items():
        for offset, kind, addend, name, target_section, target_offset in records:
            if target_section == ".sbss2":
                assert section.endswith(" -> .text"), "non-text zero-color reference"
                actual.append((offset, kind, addend, target_offset))
    assert sorted(actual) == sorted(expected), "zero-color load destinations differ"


def audit(source: Path) -> None:
    retail = read_object(ROOT / "build/GSAE01/obj/main/shader.o")
    ours = read_object(source)
    claims = parse_splits(ROOT / "config/GSAE01/splits.txt")[UNIT]
    data_sections = set(retail.sections) - {".text"}
    assert set(ours.sections) - {".text"} == data_sections, "unexpected allocated section"
    total = 0
    for name in sorted(data_sections):
        expected = retail.sections[name]
        actual = ours.sections[name]
        # MWCC tags .sdata2 writable; the reconstructed retail ELF does not.
        # DOL has no equivalent flag. Check storage type, allocation and alignment.
        assert (actual[0], actual[1] & ~1, actual[2]) == (expected[0], expected[1] & ~1, expected[2]), \
            f"{name}: section attributes differ"
        assert len(claims[name]) == 1, f"{name}: fragmented claim"
        start, end = claims[name][0]
        assert expected[3] == end - start, f"{name}: stale retail object"
        # The linker supplies trailing alignment, not an invented source object.
        alignment = expected[2]
        padded_size = (actual[3] + alignment - 1) & -alignment
        assert actual[3] == expected[3] or padded_size == expected[3], f"{name}: size differs"
        assert actual[4].ljust(expected[3], b"\0") == expected[4], f"{name}: bytes differ"
        total += expected[3]

    # These three local initializers have compiler-generated names in the source
    # object. Check every definition and reference before allowing that difference.
    audit_zero_colors(ours, source)
    for name, (_, _, offset) in ZERO_COLOR_TEMPLATES.items():
        assert retail.symbols[name][:3] == (".sbss2", offset, 4)
    audit_zero_colors(retail, ROOT / "build/GSAE01/obj/main/shader.o")

    shared = 0
    for name, symbol in retail.symbols.items():
        if (symbol[0] not in (".text", ".sdata2") and name not in ZERO_COLOR_TEMPLATES
                and not name.startswith(("gap_", "jumptable_"))):
            assert name in ours.symbols, f"missing native data symbol: {name}"
    for name in ours.symbols.keys() & retail.symbols.keys():
        a, b = ours.symbols[name], retail.symbols[name]
        if a[0] != ".text":
            assert a[:3] == b[:3], f"{name}: native symbol layout differs: {a[:3]} != {b[:3]}"
            shared += 1
    assert shared, "no native data symbols compared"

    def data_relocations(snapshot):
        # Function start offsets move while preceding functions are unfinished.
        # Keep each target function name AND its case-label offset, not that base.
        return {
            name: tuple(record[:5] for record in records)
            for name, records in snapshot.relocations.items()
            if not name.endswith(" -> .text")
        }

    assert data_relocations(ours) == data_relocations(retail), "data relocation destinations differ"
    assert ours.symbols["gTexIndMtxScale"][:3] == (".sdata2", 0x74, 4)
    assert ours.sections[".sdata2"][3] == 0xA4, "extra or missing literal"
    pool = ours.sections[".sdata2"][4]
    assert sum(pool[i:i + 4] == bytes.fromhex("3d800000") for i in range(0, len(pool), 4)) == 1

    dol = (ROOT / "orig/GSAE01/sys/main.dol").read_bytes()
    offsets = struct.unpack_from(">18I", dol, 0)
    addresses = struct.unpack_from(">18I", dol, 0x48)
    sizes = struct.unpack_from(">18I", dol, 0x90)
    pool_start, pool_end = claims[".sdata2"][0]
    text_start, text_end = claims[".text"][0]
    # Confirm the pool against the DOL as well as the regenerated retail object.
    mapped = False
    for offset, address, size in zip(offsets, addresses, sizes):
        if address <= pool_start and pool_end <= address + size:
            at = offset + pool_start - address
            assert pool.ljust(pool_end - pool_start, b"\0") == dol[at:at + pool_end - pool_start]
            mapped = True
    assert mapped, "pool is not mapped in the retail DOL"
    loads = 0
    # DOL header entries 0..6 are text. Decode direct r2-relative loads only;
    # this is not a claim to have resolved arbitrary indirect pointer accesses.
    for offset, address, size in zip(offsets[:7], addresses[:7], sizes[:7]):
        for i in range(0, size, 4):
            word = struct.unpack_from(">I", dol, offset + i)[0]
            displacement = struct.unpack_from(">h", dol, offset + i + 2)[0]
            target = 0x803E6500 + displacement
            if word >> 26 in (32, 33, 34, 35, 40, 41, 42, 43, 48, 49, 50, 51) and (word >> 16) & 31 == 2:
                if pool_start <= target < pool_end:
                    assert text_start <= address + i < text_end, f"pool load outside TU: {address + i:#x}"
                    loads += 1
    assert loads, "no retail pool loads found"
    relocations = sum(map(len, data_relocations(ours).values()))
    print(f"PASS: {total} assigned data bytes, {shared} native symbol layouts, "
          f"{relocations} data relocations, {loads} direct retail pool loads")
    print("All three anonymous zero-color templates retain their four-byte layouts and exact load destinations.")
    print("The 164-byte pool has four bytes of trailing linker alignment; text matching is a separate check.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", type=Path, default=ROOT / "build/GSAE01/src/main/shader.o")
    args = parser.parse_args()
    try:
        audit(args.object)
    except (AssertionError, KeyError, ValueError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__":
    main()
