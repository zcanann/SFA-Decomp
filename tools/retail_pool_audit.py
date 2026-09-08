#!/usr/bin/env python3
"""Audit direct retail r2 loads against current source and .sdata2 claims.

Reads the verified DOL, including unclaimed constants and unnamed text. This is
boundary evidence, not a TU inference: shared globals and compiler pooling can
also explain references crossing a claim. Indexed/address-materialized accesses
and non-r2 loads are outside this audit.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import struct

from pool_value_sequence import LOAD_WIDTHS
from version_progress import load_function_symbols, load_splits, read_dol_range, verified_dol

REPO = Path(__file__).resolve().parent.parent


def signed16(value: int) -> int:
    return (value & 0x7FFF) - (value & 0x8000)


def sda2_base(code: bytes) -> int:
    """Require the startup's adjacent lis r2 / ori-or-addi r2 sequence."""
    words = [word for (word,) in struct.iter_unpack(">I", code)]
    candidates = []
    for high, low in zip(words, words[1:]):
        if high & 0xFFFF0000 != 0x3C400000:
            continue
        if low & 0xFFFF0000 == 0x60420000:  # ori r2,r2,lo
            value = ((high & 0xFFFF) << 16) | (low & 0xFFFF)
        elif low & 0xFFFF0000 == 0x38420000:  # addi r2,r2,lo
            value = (((high & 0xFFFF) << 16) + signed16(low)) & 0xFFFFFFFF
        else:
            continue
        candidates.append(value)
    if len(candidates) != 1:
        raise ValueError(f"expected one startup r2 initialization, found {len(candidates)}")
    return candidates[0]


def direct_load(word: int, base: int) -> tuple[int, int] | None:
    width = LOAD_WIDTHS.get(word >> 26)
    if width is None or (word >> 16) & 31 != 2:
        return None
    # Updating r2 destroys the ABI base; do not silently model subsequent loads.
    if word >> 26 in (33, 35, 41, 43, 49, 51):
        raise ValueError("r2-updating load cannot be audited with a fixed SDA2 base")
    return (base + signed16(word)) & 0xFFFFFFFF, width


class SpanIndex:
    def __init__(self, spans):
        self.spans = sorted(spans, key=lambda span: span.start)
        self.starts = [span.start for span in self.spans]
        if any(a.end > b.start for a, b in zip(self.spans, self.spans[1:])):
            raise ValueError("overlapping split ranges")

    def owner(self, address: int, width: int = 1) -> str | None:
        index = bisect_right(self.starts, address) - 1
        if index >= 0:
            span = self.spans[index]
            if address + width <= span.end:
                return span.unit
        return None


@dataclass(frozen=True)
class Load:
    instruction: int
    function: str | None
    source: str | None
    address: int
    width: int
    value: str
    pool_owner: str | None


def audit(version: str, sources: list[str], root: Path = REPO) -> dict:
    config = root / "config" / version
    dol = verified_dol(root / "orig" / version / "sys/main.dol", config / "config.yml")
    functions = load_function_symbols(config / "symbols.txt")
    startup = [function for function in functions if function.name == "__init_registers"]
    if len(startup) != 1:
        raise ValueError("expected one __init_registers symbol")
    base = sda2_base(read_dol_range(dol, startup[0].address, startup[0].size))
    _, splits = load_splits(config / "splits.txt")
    text_claims = SpanIndex([span for span in splits if span.section in ("text", "init")])
    pool_claims = SpanIndex([span for span in splits if span.section == "sdata2"])
    pool = next(section for section in dol.sections if section.index == 14)
    available = {span.unit for span in splits}
    selected = sorted({source.removeprefix("src/") for source in sources})
    if missing := set(selected) - available:
        raise ValueError("sources absent from this version's splits: " + ", ".join(sorted(missing)))
    starts = [function.address for function in functions]
    loads = []
    for section in dol.text_sections:
        for offset, (word,) in enumerate(struct.iter_unpack(">I", read_dol_range(dol, section.address, section.size))):
            decoded = direct_load(word, base)
            if decoded is None:
                continue
            address, width = decoded
            if not pool.address <= address < pool.address + pool.size:
                continue
            if address + width > pool.address + pool.size:
                raise ValueError(f"load crosses the DOL .sdata2 end at 0x{address:08X}")
            instruction = section.address + offset * 4
            index = bisect_right(starts, instruction) - 1
            function = functions[index] if index >= 0 else None
            name = function.name if function and function.contains(instruction + 3) else None
            loads.append(Load(instruction, name, text_claims.owner(instruction, 4), address, width,
                              read_dol_range(dol, address, width).hex(), pool_claims.owner(address, width)))
    outgoing = [load for load in loads if load.source in selected]
    incoming = [load for load in loads if load.pool_owner in selected and load.source not in selected]
    read_bytes = {address for load in outgoing for address in range(load.address, load.address + load.width)}
    other_consumers = [load for load in loads if load.source not in selected and
                       any(address in read_bytes for address in range(load.address, load.address + load.width))]
    summaries = []
    for source in selected:
        own = [load for load in outgoing if load.source == source]
        foreign = [load for load in own if load.pool_owner != source]
        summaries.append({
            "source": source,
            "loads": len(own),
            "distinct_loads": len({(load.address, load.width) for load in own}),
            "outside_claim_loads": len(foreign),
            "outside_claim_bytes": len({address for load in foreign
                                        for address in range(load.address, load.address + load.width)
                                        if pool_claims.owner(address) != source}),
        })
    return {
        "version": version,
        "sda2_base": base,
        "scope": "direct non-updating r2 loads into DOL section 14; no ownership inference",
        "summaries": summaries,
        "loads": [asdict(load) for load in outgoing],
        "incoming": [asdict(load) for load in incoming],
        "other_consumers": [asdict(load) for load in other_consumers],
    }


def markdown(report: dict) -> str:
    lines = [f"# Retail pool audit: {report['version']}", "",
             f"Verified retail DOL; startup r2 = `0x{report['sda2_base']:08X}`.", "",
             report["scope"] + ".", "",
             "| Source | Loads | Distinct address/width pairs | Loads outside claim | Bytes outside claim |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for row in report["summaries"]:
        lines.append(f"| `{row['source']}` | {row['loads']} | {row['distinct_loads']} | "
                     f"{row['outside_claim_loads']} | {row['outside_claim_bytes']} |")
    lines += ["", "## References outside the source's pool claim", "",
              "Repeated loads of one address by one function are grouped here; JSON preserves every load.", "",
              "| Function / instruction | Pool address | Width | Bytes | Claimed owner |",
              "| --- | --- | ---: | --- | --- |"]
    seen = set()
    for load in report["loads"]:
        key = (load["source"], load["function"], load["address"], load["width"])
        if load["source"] == load["pool_owner"] or key in seen:
            continue
        seen.add(key)
        label = load["function"] or f"0x{load['instruction']:08X}"
        owner = load["pool_owner"] or "unclaimed (or spans a claim boundary)"
        lines.append(f"| `{label}` | `0x{load['address']:08X}` | {load['width']} | "
                     f"`{load['value']}` | {owner} |")
    lines += ["", f"Incoming loads from outside the selected sources: {len(report['incoming'])}.",
              f"Outside loads overlapping bytes read by the selected sources: {len(report['other_consumers'])}.",
              "Use JSON for their instruction addresses and for all loads inside claims.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", help="source paths from the selected version's splits")
    parser.add_argument("-v", "--version", default="GSAE01",
                        choices=sorted(path.parent.name for path in (REPO / "config").glob("*/config.yml")))
    parser.add_argument("--json", action="store_true", help="include every load, payload and claim")
    args = parser.parse_args(argv)
    try:
        report = audit(args.version, args.sources)
    except (OSError, ValueError, StopIteration) as error:
        parser.error(str(error) or "missing retail .sdata2 section")
    print(json.dumps(report, indent=2) if args.json else markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
