#!/usr/bin/env python3
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def section_headers(data: bytes):
    offset = struct.unpack_from(">I", data, 0x20)[0]
    size, count = struct.unpack_from(">HH", data, 0x2E)
    return [offset + index * size for index in range(count)]


def section_names(data: bytes, headers):
    string_index = struct.unpack_from(">H", data, 0x32)[0]
    string_offset = struct.unpack_from(">I", data, headers[string_index] + 0x10)[0]
    names = []
    for header in headers:
        name_offset = string_offset + struct.unpack_from(">I", data, header)[0]
        name_end = data.index(0, name_offset)
        names.append(data[name_offset:name_end].decode("ascii"))
    return names


def patch_comment_alignments(path: Path, alignments: dict[str, int]) -> None:
    data = bytearray(path.read_bytes())
    headers = section_headers(data)
    names = section_names(data, headers)
    indices = {names.index(name): alignment for name, alignment in alignments.items()}
    comment = headers[names.index(".comment")]
    comment_offset, comment_size = struct.unpack_from(">II", data, comment + 0x10)
    symtab = headers[names.index(".symtab")]
    symtab_offset, symtab_size, symtab_entry_size = struct.unpack_from(">II12xI", data, symtab + 0x10)
    symbol_count = symtab_size // symtab_entry_size
    if comment_size != 0x2C + symbol_count * 8:
        raise ValueError("unsupported CodeWarrior comment section")
    for symbol_index in range(symbol_count):
        symbol = symtab_offset + symbol_index * symtab_entry_size
        symbol_type = data[symbol + 0xC] & 0xF
        section_index = struct.unpack_from(">H", data, symbol + 0xE)[0]
        if symbol_type == 3 and section_index in indices:
            struct.pack_into(">I", data, comment_offset + 0x2C + symbol_index * 8, indices[section_index])
            del indices[section_index]
    if indices:
        raise ValueError(f"missing section symbols: {sorted(indices)}")
    path.write_bytes(data)


def main() -> int:
    object_path = Path(sys.argv[1])
    objcopy = sys.argv[2]
    alignments = dict(alignment.split("=", 1) for alignment in sys.argv[3:])
    alignments = {section: int(alignment, 0) for section, alignment in alignments.items()}
    with tempfile.TemporaryDirectory(dir=object_path.parent) as directory:
        aligned = Path(directory) / "aligned.o"
        flags = []
        for section, alignment in alignments.items():
            flags.extend(("--set-section-alignment", f"{section}={alignment}"))
        subprocess.run([objcopy, *flags, object_path, aligned], check=True)
        patch_comment_alignments(aligned, alignments)
        os.replace(aligned, object_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
