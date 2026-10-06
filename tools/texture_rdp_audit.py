#!/usr/bin/env python3
"""Compare the retained texture RDP tables to verified retail DOLs and an optional donor.

Compiles the actual data declarations with native pointers, then checks every
command word, preset pointer, mask and forced flag against retail. The optional
Dinosaur Planet comparison expands that checkout's GBI macros independently;
it supplies source-lineage evidence, not a claim that the GC renderer uses RDP.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from orig.dol_tables import DolFile

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ("GSAE01", "GSAE01_rev1", "GSAJ01", "GSAP01", "GSAP01_rev1")
PRELUDE = """
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef int8_t s8;
typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32;
typedef uint64_t u64; typedef int64_t s64;
typedef float f32; typedef double f64;
#define STATIC_ASSERT(...)
"""


def probe(declarations, arrays, preset, pointer_fields, flag_fields, command_type, words, includes=()):
    """Read the compiler's data interpretation, including native preset pointers."""
    code = [PRELUDE, declarations, f"static const char* nameOf({command_type}* p) {{"]
    code += [f'if (p == {name}) return "{name}";' for name in arrays]
    code += ['assert(0 && "preset points outside command arrays"); return ""; }',
             'int main(void) { assert(sizeof(void*) == 8);']
    for name in arrays:
        code += [f'printf("C {name}");',
                 f'for (unsigned i = 0; i < sizeof({name}) / sizeof({command_type}); i++) {{',
                 f'printf(" %08x %08x", {name}[i].{words[0]}, {name}[i].{words[1]});',
                 '} puts("");']
    code += [f'for (unsigned i = 0; i < sizeof({preset}) / sizeof({preset}[0]); i++) {{',
             f'assert((uintptr_t){preset}[i].{pointer_fields[0]} > UINT32_MAX);',
             f'assert((uintptr_t){preset}[i].{pointer_fields[1]} > UINT32_MAX);',
             f'printf("P %s %s %x %x\\n", nameOf({preset}[i].{pointer_fields[0]}),',
             f'nameOf({preset}[i].{pointer_fields[1]}), {preset}[i].{flag_fields[0]},',
             f'{preset}[i].{flag_fields[1]}); }}']
    if command_type == "TextureRdpCommand":
        code += ['printf("T");',
                 'for (unsigned i = 0; i < 7; i++) { for (unsigned j = 0; j < 8; j++) {',
                 'printf(" %08x %08x", gTextureRdpMipmapTiles[i][j].word0,',
                 'gTextureRdpMipmapTiles[i][j].word1); } } puts("");']
    code += ['return 0; }']
    with tempfile.TemporaryDirectory(prefix="texture-rdp-") as directory:
        path = Path(directory) / "tables.c"
        executable = Path(directory) / "tables"
        path.write_text("\n".join(code))
        subprocess.run(["clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        *[f"-I{path}" for path in includes], str(path), "-o", str(executable)],
                       check=True, timeout=30)
        output = subprocess.check_output([str(executable)], text=True, timeout=30)
    commands, presets, tiles = {}, [], []
    for line in output.splitlines():
        fields = line.split()
        if fields[0] == "C":
            commands[fields[1]] = [int(value, 16) for value in fields[2:]]
        elif fields[0] == "P":
            presets.append((*fields[1:3], int(fields[3], 16), int(fields[4], 16)))
        elif fields[0] == "T":
            tiles = [int(value, 16) for value in fields[1:]]
    return commands, presets, tiles


def source_tables():
    source = (ROOT / "src/main/texture.c").read_text()
    start = source.index("typedef struct TextureRdpCommand")
    end = source.index("char sTexRestructAllocFailedMessage", start)
    data = source[start:end]
    arrays = re.findall(r"TextureRdpCommand (\w+)\[\d+\] =", data)
    assert len(arrays) == 47
    commands, presets, tiles = probe(data, arrays, "gTextureRdpPresets",
                                    ("combineModes", "otherModes"), ("renderFlagMask", "forcedRenderFlags"),
                                    "TextureRdpCommand", ("word0", "word1"))
    assert len(presets) == 52 and len(tiles) == 112
    for combine, modes, mask, forced in presets:
        assert all(value >> 24 == 0xFC for value in commands[combine][::2]), combine
        assert all(value >> 24 == 0xEF for value in commands[modes][::2]), modes
        for flags in range(16):
            index = (flags & mask) | forced
            assert (index >> 3) < len(commands[combine]) // 2
            assert index < len(commands[modes]) // 2
            if (index & 7) < 4:
                assert index + 4 < len(commands[modes]) // 2
    assert all(value >> 24 in (0xF5, 0xF2) for value in tiles[::2])
    return commands, presets, tiles


def verify_retail(version, commands, presets, tiles):
    config = ROOT / "config" / version
    expected = re.search(r"^hash: (\w+)", (config / "config.yml").read_text(), re.M)[1]
    dol = DolFile(ROOT / "orig" / version / "sys/main.dol")
    assert hashlib.sha1(dol.data).hexdigest() == expected, f"{version}: original DOL hash mismatch"
    symbols = {}
    needed = set(commands) | {"gTextureRdpPresets", "gTextureRdpMipmapTiles"}
    for name, address, size in re.findall(
            r"^(\w+) = \.data:0x([0-9A-Fa-f]+);.*?size:0x([0-9A-Fa-f]+)",
            (config / "symbols.txt").read_text(), re.M):
        if name not in needed:
            continue
        assert name not in symbols, f"duplicate symbol: {name}"
        symbols[name] = int(address, 16), int(size, 16)
    tables = dict(commands)
    tables["gTextureRdpPresets"] = [word for a, b, mask, forced in presets
                                    for word in (symbols[a][0], symbols[b][0], mask, forced)]
    tables["gTextureRdpMipmapTiles"] = tiles
    ranges = []
    for name, values in tables.items():
        address, size = symbols[name]
        encoded = struct.pack(f">{len(values)}I", *values)
        assert size == len(encoded), (version, name, "symbol size")
        offset = dol.addr_to_offset(address)
        assert offset is not None and dol.addr_to_offset(address + size - 1) == offset + size - 1
        assert dol.data[offset:offset + size] == encoded, (version, name, "retail contents/pointers")
        ranges.append((address, address + size))
    ranges.sort()
    assert all(end == following for (_, end), (following, _) in zip(ranges, ranges[1:]))
    return {"dol_sha1": expected, "exact_data_bytes": sum(size for _, size in
            (symbols[name] for name in tables)), "command_arrays": len(commands), "presets": len(presets)}


def verify_reference(reference, commands, presets, tiles):
    source_path = reference / "src/texture.c"
    header_path = reference / "include/sys/gfx/texture.h"
    source = source_path.read_text()
    header_lines = header_path.read_text().splitlines()
    macros, i = [], 0
    while i < len(header_lines):
        if header_lines[i].startswith("#define"):
            block = header_lines[i]
            while header_lines[i].endswith("\\"):
                i += 1
                block += "\n" + header_lines[i]
            macros.append(block)
        i += 1
    arrays = list(re.finditer(r"Gfx (\w+)\[\] = \{.*?^\};", source, re.M | re.S))
    assert len(arrays) == 54, "reference command/tile inventory changed"
    declarations = '\n'.join([
        '#define _ULTRATYPES_H_', '#define _LANGUAGE_C', '#define F3DEX_GBI_2',
        '#define TRUE 1', '#define FALSE 0', '#include "PR/mbi.h"', '#include "PR/gbi.h"',
        '#include "gbi_extra.h"', *macros, *[match[0] for match in arrays],
        re.search(r"struct PointersInts\s*\{.*?\};", source, re.S)[0],
        re.search(r"struct PointersInts pointersIntsArray\[52\] = \{.*?^\};", source, re.M | re.S)[0],
    ])
    donor_commands, donor_presets, _ = probe(
        declarations, [match[1] for match in arrays], "pointersIntsArray",
        ("prts[0]", "prts[1]"), ("valA", "valB"), "Gfx", ("words.w0", "words.w1"),
        (reference / "include",))
    mapping = dict(zip(list(donor_commands)[:47], commands))
    for old, new in mapping.items():
        assert donor_commands[old] == commands[new], (old, new, "reference command words")
    assert [(mapping[a], mapping[b], mask, forced) for a, b, mask, forced in donor_presets] == presets
    assert [word for name in list(donor_commands)[47:] for word in donor_commands[name]] == tiles
    files = [source_path, header_path, reference / "include/gbi_extra.h",
             reference / "include/PR/gbi.h", reference / "include/PR/mbi.h"]
    return {"mapping": mapping, "file_sha256": {str(path.relative_to(reference)):
            hashlib.sha256(path.read_bytes()).hexdigest() for path in files}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", choices=VERSIONS, default="GSAE01")
    parser.add_argument("--all-versions", action="store_true")
    parser.add_argument("--reference", type=Path, help="optional Dinosaur Planet checkout (read only)")
    args = parser.parse_args()
    commands, presets, tiles = source_tables()
    result = {"versions": {version: verify_retail(version, commands, presets, tiles)
                           for version in (VERSIONS if args.all_versions else (args.version,))},
              "preset_index_cases": len(presets) * 16}
    if args.reference:
        result["reference"] = verify_reference(args.reference.resolve(), commands, presets, tiles)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
