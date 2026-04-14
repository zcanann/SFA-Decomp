from __future__ import annotations

import argparse
import csv
import io
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


SYMBOL_FUNCTION_RE = re.compile(
    r"^(\S+)\s*=\s*\.(\S+):0x([0-9A-Fa-f]+); // type:function size:0x([0-9A-Fa-f]+)"
)


@dataclass(frozen=True)
class DolSection:
    index: int
    offset: int
    address: int
    size: int


@dataclass(frozen=True)
class FunctionSymbol:
    name: str
    section: str
    address: int
    size: int

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + self.size


@dataclass(frozen=True)
class TableStoreXref:
    load_address: int
    store_address: int
    loaded_table_address: int
    object_reg: int
    store_disp: int
    function_name: str | None
    function_start: int | None


@dataclass(frozen=True)
class TableCandidate:
    section_index: int
    start_address: int
    end_address: int
    slot_count: int
    preceding_word_1: int | None
    preceding_word_0: int | None
    method_addresses: tuple[int, ...]
    store_xrefs: tuple[TableStoreXref, ...]

    @property
    def kind(self) -> str:
        has_zero_prefix = self.preceding_word_0 == 0 or self.preceding_word_1 == 0
        has_zero_store = any(xref.store_disp == 0 for xref in self.store_xrefs)
        near_start = any(
            0 <= xref.loaded_table_address - self.start_address <= 8
            for xref in self.store_xrefs
        )
        if has_zero_prefix and has_zero_store and near_start:
            return "vtable-like"
        if self.store_xrefs:
            return "callback-table-like"
        return "pointer-table"


class DolFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        section_offsets = [struct.unpack_from(">I", self.data, index * 4)[0] for index in range(18)]
        section_addrs = [struct.unpack_from(">I", self.data, 0x48 + index * 4)[0] for index in range(18)]
        section_sizes = [struct.unpack_from(">I", self.data, 0x90 + index * 4)[0] for index in range(18)]
        self.sections = [
            DolSection(
                index=index,
                offset=section_offsets[index],
                address=section_addrs[index],
                size=section_sizes[index],
            )
            for index in range(18)
            if section_sizes[index]
        ]
        self.text_sections = [section for section in self.sections if section.index <= 6]

    def addr_to_offset(self, address: int) -> int | None:
        for section in self.sections:
            if section.address <= address < section.address + section.size:
                return section.offset + (address - section.address)
        return None

    def is_text_pointer(self, address: int) -> bool:
        for section in self.text_sections:
            if section.address <= address < section.address + section.size:
                return True
        return False

    def read_u32(self, address: int) -> int:
        offset = self.addr_to_offset(address)
        if offset is None:
            raise ValueError(f"Address 0x{address:08X} is not inside a loaded DOL section")
        return struct.unpack_from(">I", self.data, offset)[0]


def load_function_symbols(path: Path | None) -> list[FunctionSymbol]:
    if path is None or not path.is_file():
        return []
    functions: list[FunctionSymbol] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SYMBOL_FUNCTION_RE.match(line)
        if match is None:
            continue
        functions.append(
            FunctionSymbol(
                name=match.group(1),
                section=match.group(2),
                address=int(match.group(3), 16),
                size=int(match.group(4), 16),
            )
        )
    functions.sort(key=lambda item: item.address)
    return functions


def function_for_address(functions: list[FunctionSymbol], address: int) -> FunctionSymbol | None:
    low = 0
    high = len(functions)
    while low < high:
        mid = (low + high) // 2
        if functions[mid].address <= address:
            low = mid + 1
        else:
            high = mid
    index = low - 1
    if index < 0:
        return None
    function = functions[index]
    return function if function.contains(address) else None


def format_function_name(function: FunctionSymbol | None, address: int) -> str:
    if function is None:
        return f"0x{address:08X}"
    offset = address - function.address
    if offset == 0:
        return function.name
    return f"{function.name}+0x{offset:X}"


def signed_16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def find_pointer_tables(
    dol: DolFile,
    min_methods: int,
    max_methods: int,
) -> list[TableCandidate]:
    candidates: list[TableCandidate] = []
    for section in dol.sections:
        if section.index <= 10:
            continue

        run_start: int | None = None
        methods: list[int] = []
        for rel in range(0, section.size, 4):
            address = section.address + rel
            value = dol.read_u32(address)
            if dol.is_text_pointer(value):
                if run_start is None:
                    run_start = address
                    methods = []
                methods.append(value)
                continue

            if run_start is not None and min_methods <= len(methods) <= max_methods:
                prefix_1 = dol.read_u32(run_start - 8) if run_start - 8 >= section.address else None
                prefix_0 = dol.read_u32(run_start - 4) if run_start - 4 >= section.address else None
                candidates.append(
                    TableCandidate(
                        section_index=section.index,
                        start_address=run_start,
                        end_address=run_start + (len(methods) * 4),
                        slot_count=len(methods),
                        preceding_word_1=prefix_1,
                        preceding_word_0=prefix_0,
                        method_addresses=tuple(methods),
                        store_xrefs=(),
                    )
                )
            run_start = None
            methods = []

        if run_start is not None and min_methods <= len(methods) <= max_methods:
            prefix_1 = dol.read_u32(run_start - 8) if run_start - 8 >= section.address else None
            prefix_0 = dol.read_u32(run_start - 4) if run_start - 4 >= section.address else None
            candidates.append(
                TableCandidate(
                    section_index=section.index,
                    start_address=run_start,
                    end_address=run_start + (len(methods) * 4),
                    slot_count=len(methods),
                    preceding_word_1=prefix_1,
                    preceding_word_0=prefix_0,
                    method_addresses=tuple(methods),
                    store_xrefs=(),
                )
            )
    return candidates


def candidate_for_address(candidates: list[TableCandidate], address: int) -> TableCandidate | None:
    for candidate in candidates:
        if candidate.start_address <= address < candidate.end_address:
            return candidate
    return None


def attach_store_xrefs(
    dol: DolFile,
    candidates: list[TableCandidate],
    functions: list[FunctionSymbol],
    load_window: int = 3,
    store_window: int = 12,
) -> list[TableCandidate]:
    by_start: dict[int, list[TableStoreXref]] = {candidate.start_address: [] for candidate in candidates}
    for section in dol.text_sections:
        words = [
            struct.unpack_from(">I", dol.data, section.offset + rel)[0]
            for rel in range(0, section.size, 4)
        ]
        for index, first_word in enumerate(words):
            if first_word >> 26 != 15:
                continue
            if ((first_word >> 16) & 31) != 0:
                continue

            reg = (first_word >> 21) & 31
            high_imm = first_word & 0xFFFF
            for next_index in range(index + 1, min(index + load_window + 1, len(words))):
                second_word = words[next_index]
                opcode = second_word >> 26
                ra = (second_word >> 16) & 31
                rd = (second_word >> 21) & 31
                loaded_address: int | None = None
                if opcode == 14 and ra == reg:
                    loaded_address = ((signed_16(high_imm) << 16) + signed_16(second_word & 0xFFFF)) & 0xFFFFFFFF
                elif opcode == 24 and ra == reg and rd == reg:
                    loaded_address = ((high_imm << 16) | (second_word & 0xFFFF)) & 0xFFFFFFFF
                if loaded_address is None:
                    continue

                candidate = candidate_for_address(candidates, loaded_address)
                if candidate is None:
                    continue

                for store_index in range(next_index + 1, min(next_index + store_window + 1, len(words))):
                    store_word = words[store_index]
                    store_opcode = store_word >> 26
                    rs = (store_word >> 21) & 31
                    ra_store = (store_word >> 16) & 31
                    if store_opcode not in (36, 37) or rs != reg:
                        continue
                    if ra_store not in (3, 26, 27, 28, 29, 30, 31):
                        continue

                    load_address = section.address + (index * 4)
                    store_address = section.address + (store_index * 4)
                    function = function_for_address(functions, load_address)
                    by_start[candidate.start_address].append(
                        TableStoreXref(
                            load_address=load_address,
                            store_address=store_address,
                            loaded_table_address=loaded_address,
                            object_reg=ra_store,
                            store_disp=signed_16(store_word & 0xFFFF),
                            function_name=function.name if function is not None else None,
                            function_start=function.address if function is not None else None,
                        )
                    )
                break

    updated: list[TableCandidate] = []
    for candidate in candidates:
        xrefs = sorted(
            by_start[candidate.start_address],
            key=lambda item: (item.load_address, item.store_address, item.loaded_table_address),
        )
        updated.append(
            TableCandidate(
                section_index=candidate.section_index,
                start_address=candidate.start_address,
                end_address=candidate.end_address,
                slot_count=candidate.slot_count,
                preceding_word_1=candidate.preceding_word_1,
                preceding_word_0=candidate.preceding_word_0,
                method_addresses=candidate.method_addresses,
                store_xrefs=tuple(xrefs),
            )
        )
    return updated


def table_matches(candidate: TableCandidate, terms: list[str], functions: list[FunctionSymbol]) -> bool:
    if not terms:
        return True
    haystacks: list[str] = [
        f"{candidate.start_address:08X}",
        candidate.kind,
    ]
    for method_address in candidate.method_addresses[:8]:
        haystacks.append(format_function_name(function_for_address(functions, method_address), method_address))
    for xref in candidate.store_xrefs:
        haystacks.append(f"{xref.load_address:08X}")
        if xref.function_name is not None:
            haystacks.append(xref.function_name)
    folded = " ".join(haystacks).lower()
    return all(term.lower() in folded for term in terms)


def summary_markdown(
    candidates: list[TableCandidate],
    functions: list[FunctionSymbol],
    stores_only: bool,
    limit: int | None,
) -> str:
    visible = [candidate for candidate in candidates if candidate.store_xrefs or not stores_only]
    if limit is not None:
        visible = visible[:limit]

    lines: list[str] = []
    lines.append("# `orig/GSAE01/sys/main.dol` vtable-style table audit")
    lines.append("")
    lines.append(f"- Candidate tables scanned: {len(candidates)}")
    lines.append(f"- Tables shown: {len(visible)}")
    lines.append(f"- Filter: {'store-backed only' if stores_only else 'all candidates'}")

    for candidate in visible:
        lines.append("")
        lines.append(
            f"## `{candidate.kind}` at `0x{candidate.start_address:08X}`"
            f" (`{candidate.slot_count}` slots, section `{candidate.section_index}`)"
        )
        lines.append(
            f"- Prefix words: `0x{candidate.preceding_word_1 or 0:08X}`,"
            f" `0x{candidate.preceding_word_0 or 0:08X}`"
        )
        method_names = [
            format_function_name(function_for_address(functions, address), address)
            for address in candidate.method_addresses[:6]
        ]
        lines.append(f"- Leading methods: {', '.join(f'`{name}`' for name in method_names)}")
        if not candidate.store_xrefs:
            continue
        lines.append("- Constructor-style stores:")
        for xref in candidate.store_xrefs[:6]:
            function = function_for_address(functions, xref.load_address)
            lines.append(
                f"  - `{format_function_name(function, xref.load_address)}`"
                f" loads `0x{xref.loaded_table_address:08X}` and stores it at"
                f" `r{xref.object_reg}+0x{xref.store_disp:X}`"
            )
    lines.append("")
    return "\n".join(lines)


def summary_csv(candidates: list[TableCandidate], functions: list[FunctionSymbol], stores_only: bool) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "kind",
            "table_address",
            "slot_count",
            "prefix_word_1",
            "prefix_word_0",
            "first_methods",
            "xref_function",
            "xref_load_address",
            "loaded_table_address",
            "store_address",
            "object_reg",
            "store_disp",
        ]
    )
    for candidate in candidates:
        if stores_only and not candidate.store_xrefs:
            continue
        first_methods = "; ".join(
            format_function_name(function_for_address(functions, address), address)
            for address in candidate.method_addresses[:6]
        )
        if candidate.store_xrefs:
            for xref in candidate.store_xrefs:
                function = function_for_address(functions, xref.load_address)
                writer.writerow(
                    [
                        candidate.kind,
                        f"0x{candidate.start_address:08X}",
                        candidate.slot_count,
                        f"0x{candidate.preceding_word_1 or 0:08X}",
                        f"0x{candidate.preceding_word_0 or 0:08X}",
                        first_methods,
                        format_function_name(function, xref.load_address),
                        f"0x{xref.load_address:08X}",
                        f"0x{xref.loaded_table_address:08X}",
                        f"0x{xref.store_address:08X}",
                        f"r{xref.object_reg}",
                        xref.store_disp,
                    ]
                )
            continue
        writer.writerow(
            [
                candidate.kind,
                f"0x{candidate.start_address:08X}",
                candidate.slot_count,
                f"0x{candidate.preceding_word_1 or 0:08X}",
                f"0x{candidate.preceding_word_0 or 0:08X}",
                first_methods,
                "",
                "",
                "",
                "",
                "",
                "",
            ]
        )
    return buffer.getvalue()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find vtable-style function-pointer tables in orig/GSAE01/sys/main.dol."
    )
    parser.add_argument(
        "--dol",
        type=Path,
        default=Path("orig/GSAE01/sys/main.dol"),
        help="Path to the retail EN main.dol",
    )
    parser.add_argument(
        "--symbols",
        type=Path,
        default=Path("config/GSAE01/symbols.txt"),
        help="Path to the current symbol file used for function resolution",
    )
    parser.add_argument(
        "--min-methods",
        type=int,
        default=3,
        help="Minimum number of consecutive text pointers to treat as a table",
    )
    parser.add_argument(
        "--max-methods",
        type=int,
        default=128,
        help="Maximum number of consecutive text pointers to treat as a table",
    )
    parser.add_argument(
        "--stores-only",
        action="store_true",
        help="Show only tables with constructor-style stores into object registers",
    )
    parser.add_argument(
        "--search",
        nargs="+",
        default=[],
        help="Filter by table address, kind, method name, or xref function name",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of candidates to print after filtering",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "csv"),
        default="markdown",
        help="Output format",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    dol = DolFile(args.dol)
    functions = load_function_symbols(args.symbols)
    candidates = find_pointer_tables(dol, min_methods=args.min_methods, max_methods=args.max_methods)
    candidates = attach_store_xrefs(dol, candidates, functions)
    candidates.sort(
        key=lambda item: (
            -len(item.store_xrefs),
            0 if item.kind == "vtable-like" else 1,
            item.start_address,
        )
    )
    candidates = [candidate for candidate in candidates if table_matches(candidate, args.search, functions)]

    if args.format == "csv":
        sys.stdout.write(summary_csv(candidates, functions, stores_only=args.stores_only))
    else:
        sys.stdout.write(
            summary_markdown(
                candidates,
                functions,
                stores_only=args.stores_only,
                limit=args.limit,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
