"""Compare a unit's target/current .sdata2 order and first text references."""

from __future__ import annotations

import argparse
import bisect
import re
import struct
import subprocess
from pathlib import Path

from function_objdump import load_units, resolve_unit


SYMBOL_RE = re.compile(
    r"^([0-9a-fA-F]+)\s+\w+\s+(?:F|O)\s+(\.text|\.sdata2)\s+"
    r"[0-9a-fA-F]+\s+(.+)$"
)
RELOC_RE = re.compile(r"^([0-9a-fA-F]{8})\s+R_PPC_EMB_SDA21\s+([^+\s]+)")


def run(*args: str | Path) -> str:
    return subprocess.check_output([str(arg) for arg in args], text=True)


def section_bytes(objcopy: Path, obj: Path) -> bytes:
    return subprocess.check_output(
        [str(objcopy), "-O", "binary", "--only-section=.sdata2", str(obj), "/dev/stdout"]
    )


def symbol_tables(objdump: Path, obj: Path) -> tuple[list[tuple[int, str]], dict[str, int]]:
    functions: list[tuple[int, str]] = []
    pool_symbols: dict[str, int] = {}
    for line in run(objdump, "-t", obj).splitlines():
        match = SYMBOL_RE.match(line.strip())
        if match is None:
            continue
        address = int(match.group(1), 16)
        section = match.group(2)
        name = match.group(3)
        if section == ".text":
            functions.append((address, name))
        else:
            pool_symbols[name] = address
    functions.sort()
    return functions, pool_symbols


def first_references(objdump: Path, obj: Path) -> dict[int, tuple[int, str, str]]:
    functions, pool_symbols = symbol_tables(objdump, obj)
    function_addresses = [address for address, _ in functions]
    references: dict[int, tuple[int, str, str]] = {}
    in_text = False
    for line in run(objdump, "-r", obj).splitlines():
        if line.startswith("RELOCATION RECORDS FOR [.text]"):
            in_text = True
            continue
        if in_text and line.startswith("RELOCATION RECORDS FOR "):
            break
        if not in_text:
            continue
        match = RELOC_RE.match(line.strip())
        if match is None:
            continue
        text_offset = int(match.group(1), 16)
        symbol = match.group(2)
        pool_offset = pool_symbols.get(symbol)
        if pool_offset is None or pool_offset in references:
            continue
        index = bisect.bisect_right(function_addresses, text_offset) - 1
        if index >= 0:
            function_address, function = functions[index]
            function_offset = text_offset - function_address
        else:
            function = "?"
            function_offset = text_offset
        references[pool_offset] = (function_offset, function, symbol)
    return references


def describe_reference(reference: tuple[int, str, str] | None) -> str:
    if reference is None:
        return "-"
    offset, function, symbol = reference
    return f"{function}+0x{offset:x} ({symbol})"


def float_at(data: bytes, offset: int) -> str:
    if offset + 4 > len(data):
        return "-"
    value = struct.unpack_from(">f", data, offset)[0]
    return f"{value:g}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", help="unit name or source path accepted by tools/ndiff.py")
    parser.add_argument("-v", "--version", default="GSAE01")
    parser.add_argument("--start", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--end", type=lambda value: int(value, 0))
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    build = root / "build" / args.version
    unit = resolve_unit(load_units(build / "config.json"), args.unit)
    target = root / unit["object"]
    current = root / unit["object"].replace(
        f"build/{args.version}/obj/", f"build/{args.version}/src/"
    )
    objdump = root / "build/binutils/powerpc-eabi-objdump"
    objcopy = root / "build/binutils/powerpc-eabi-objcopy"

    target_data = section_bytes(objcopy, target)
    current_data = section_bytes(objcopy, current)
    target_refs = first_references(objdump, target)
    current_refs = first_references(objdump, current)
    end = args.end if args.end is not None else max(len(target_data), len(current_data))

    print("off  target     target first reference                         current    current first reference")
    for offset in range(args.start, end, 4):
        target_ref = describe_reference(target_refs.get(offset))
        current_ref = describe_reference(current_refs.get(offset))
        print(
            f"{offset:03x}  {float_at(target_data, offset):>9}  {target_ref:<45} "
            f"{float_at(current_data, offset):>9}  {current_ref}"
        )


if __name__ == "__main__":
    main()
