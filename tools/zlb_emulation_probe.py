#!/usr/bin/env python3
"""Compare retail and compiled zlb in PPC emulation (optional unicorn package).

Build build/GSAE01/src/main/zlb.o first. This executes the complete functions,
including their own tables, on fixed/dynamic streams and a stored-copy witness.
The stored witness deliberately preserves retail's overlapping-halfword LEN bug;
it is not an RFC1951 conformance test. No source or build config is modified.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import zlib

from orig.dol_vtables import DolFile, load_function_symbols


ROOT = Path(__file__).resolve().parents[1]
SOURCE = 0x81400000
DESTINATION = 0x81500000
RETURN = 0x81700000
STACK = 0x817FF000


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def cases() -> list[tuple[str, bytes, bytes]]:
    # Retail LEN = 0x0000 | (0x0001 << 8) = 256. The following 0xAB exposes
    # post-decrement's extra copy without relying on a crash or invalid memory.
    payload = bytes(range(256))
    result = [("stored", bytes.fromhex("78 9c 01 00 00 01 00") + payload + b"\xab\xcd", payload)]
    payload = bytes(random.Random(73).choices(range(8), k=12000))
    for name, strategy, block_type in (("fixed", zlib.Z_FIXED, 1), ("dynamic", zlib.Z_DEFAULT_STRATEGY, 2)):
        compressor = zlib.compressobj(6, zlib.DEFLATED, zlib.MAX_WBITS, 8, strategy)
        compressed = compressor.compress(payload) + compressor.flush()
        if (compressed[2] >> 1) & 3 != block_type:
            raise RuntimeError(f"Host zlib did not generate a {name} block")
        result.append((name, compressed + bytes(8), payload))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", type=Path, default=ROOT / "build/GSAE01/src/main/zlb.o")
    parser.add_argument("--output", type=Path, default=ROOT / "build/zlb-emulation")
    args = parser.parse_args()
    try:
        import unicorn as uc
        from unicorn import ppc_const as ppc
    except ImportError:
        parser.error("This optional probe requires the unicorn Python package")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    elf = output / "zlb.elf"
    subprocess.run([str(ROOT / "build/binutils/powerpc-eabi-ld"), "-Ttext=0x81000000",
                    "-e", "zlbDecompress", str(args.object.resolve()), "-o", str(elf)],
                   check=True, timeout=30)
    data = elf.read_bytes()
    nm = subprocess.check_output([str(ROOT / "build/binutils/powerpc-eabi-nm"), str(elf)],
                                 text=True, timeout=30)
    symbols = {fields[2]: int(fields[0], 16) for line in nm.splitlines()
               if len(fields := line.split()) == 3}
    elf_segments = []
    ph = word(data, 28)
    entry_size, count = struct.unpack_from(">HH", data, 42)
    for index in range(count):
        offset = ph + index * entry_size
        if word(data, offset) == 1:
            start, address, size = (word(data, offset + field) for field in (4, 8, 16))
            elf_segments.append((address, data[start:start + size]))
    dol = DolFile(ROOT / "orig/GSAE01/sys/main.dol")
    retail_entry = next(fn.address for fn in load_function_symbols(ROOT / "config/GSAE01/symbols.txt")
                        if fn.name == "zlbDecompress")
    retail_segments = [(s.address, dol.data[s.offset:s.offset + s.size]) for s in dol.sections]
    images = [("retail", retail_entry, retail_segments, 0, 0),
              ("source", word(data, 24), elf_segments,
               symbols.get("_SDA_BASE_", 0), symbols.get("_SDA2_BASE_", 0))]
    results = []
    for name, compressed, expected in cases():
        for version, entry, segments, sda1, sda2 in images:
            emulator = uc.Uc(uc.UC_ARCH_PPC, uc.UC_MODE_32 | uc.UC_MODE_BIG_ENDIAN)
            emulator.mem_map(0x80000000, 0x1800000)
            for address, segment in segments:
                if segment:
                    emulator.mem_write(address, segment)
            emulator.mem_write(SOURCE, compressed)
            emulator.mem_write(DESTINATION, b"\xcd" * (len(expected) + 16))
            # Retail zlb uses absolute addresses. GNU ld may relax source ELF
            # accesses to its own small-data bases, so initialize those as well.
            for register, value in ((ppc.UC_PPC_REG_1, STACK), (ppc.UC_PPC_REG_3, SOURCE),
                                    (ppc.UC_PPC_REG_2, sda2), (ppc.UC_PPC_REG_13, sda1),
                                    (ppc.UC_PPC_REG_4, len(compressed)), (ppc.UC_PPC_REG_5, DESTINATION),
                                    (ppc.UC_PPC_REG_6, DESTINATION + 0x30000), (ppc.UC_PPC_REG_LR, RETURN)):
                emulator.reg_write(register, value)
            emulator.emu_start(entry, RETURN, count=3000000)
            actual = bytes(emulator.mem_read(DESTINATION, len(expected) + 16))
            row = {"case": name, "version": version,
                   "returned": emulator.reg_read(ppc.UC_PPC_REG_PC) == RETURN,
                   "return_value": emulator.reg_read(ppc.UC_PPC_REG_3),
                   "output_correct": actual[:len(expected)] == expected,
                   "canary_intact": actual[len(expected):] == b"\xcd" * 16}
            results.append(row)
            print(json.dumps(row))
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if not all(r["returned"] and r["return_value"] == 0 and r["output_correct"] and r["canary_intact"]
               for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
