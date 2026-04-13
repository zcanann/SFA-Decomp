from __future__ import annotations

import argparse
import bisect
import re
from dataclasses import dataclass
from pathlib import Path


SYMBOL_RE = re.compile(
    r"^(?P<name>\S+)\s*=\s*(?P<section>\S+):0x(?P<address>[0-9A-Fa-f]+);"
    r"(?:\s*//\s*(?P<meta>.*))?$"
)
SIZE_RE = re.compile(r"\bsize:0x([0-9A-Fa-f]+)\b")


@dataclass(frozen=True)
class Symbol:
    name: str
    section: str
    address: int
    size: int | None
    meta: str


def load_symbols(path: Path) -> list[Symbol]:
    symbols: list[Symbol] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = SYMBOL_RE.match(line.strip())
        if match is None:
            continue

        meta = match.group("meta") or ""
        size_match = SIZE_RE.search(meta)
        symbols.append(
            Symbol(
                name=match.group("name"),
                section=match.group("section"),
                address=int(match.group("address"), 16),
                size=int(size_match.group(1), 16) if size_match else None,
                meta=meta,
            )
        )

    symbols.sort(key=lambda symbol: (symbol.address, symbol.name))
    return symbols


def parse_query(query: str) -> int | str:
    value = query.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    if value.isdigit():
        return int(value, 16)
    return value


def find_center(symbols: list[Symbol], query: int | str) -> int:
    if isinstance(query, str):
        for index, symbol in enumerate(symbols):
            if symbol.name == query:
                return index
        raise SystemExit(f"Symbol not found: {query}")

    addresses = [symbol.address for symbol in symbols]
    index = bisect.bisect_left(addresses, query)
    if index >= len(symbols):
        return len(symbols) - 1
    if symbols[index].address == query or index == 0:
        return index
    prev_distance = query - symbols[index - 1].address
    next_distance = symbols[index].address - query
    return index - 1 if prev_distance <= next_distance else index


def format_symbol(symbol: Symbol) -> str:
    size_text = f" size=0x{symbol.size:X}" if symbol.size is not None else ""
    meta_text = f" // {symbol.meta}" if symbol.meta else ""
    return f"{symbol.name:40} {symbol.section:12} 0x{symbol.address:08X}{size_text}{meta_text}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print neighboring symbols around an address or symbol name."
    )
    parser.add_argument("query", help="Symbol name or hex address")
    parser.add_argument(
        "-v",
        "--version",
        default="GSAE01",
        help="Version directory under config/ (default: GSAE01)",
    )
    parser.add_argument(
        "-n",
        "--neighbors",
        type=int,
        default=5,
        help="Number of symbols to print before and after the center (default: 5)",
    )
    args = parser.parse_args()

    symbols_path = Path("config") / args.version / "symbols.txt"
    if not symbols_path.is_file():
        raise SystemExit(f"Missing symbols file: {symbols_path}")

    symbols = load_symbols(symbols_path)
    if not symbols:
        raise SystemExit(f"No symbols parsed from {symbols_path}")

    center = find_center(symbols, parse_query(args.query))
    start = max(0, center - args.neighbors)
    end = min(len(symbols), center + args.neighbors + 1)

    for index in range(start, end):
        prefix = ">" if index == center else " "
        print(f"{prefix} {format_symbol(symbols[index])}")


if __name__ == "__main__":
    main()
