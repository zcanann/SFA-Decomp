from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


PRINTABLE_RE = re.compile(rb"[ -~]{4,}")
SOURCE_TAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_./-]*\.(?:c|h)\b")
FILE_TOKEN_RE = re.compile(r"(?:/?[A-Za-z0-9_%./-]+)\.(?:bin|tab|romlist(?:\.zlb)?|thp)\b", re.IGNORECASE)
SYMBOL_FUNCTION_RE = re.compile(
    r"^(\S+)\s*=\s*\.(\S+):0x([0-9A-Fa-f]+); // type:function size:0x([0-9A-Fa-f]+)"
)
FILE_TABLE_ENTRY_RE = re.compile(
    r"^\s*'([^']+)':\s+\{\s+'bin':\s+(.+?),\s+'tab':\s+(.+?)\s*\},?\s*$"
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
class DolString:
    address: int
    section_index: int
    text: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class StringXref:
    xref_address: int
    pair_address: int
    target_address: int
    target_text: str
    pair_kind: str
    function_name: str | None
    function_start: int | None


@dataclass(frozen=True)
class FamilyHint:
    family: str
    bin_slots: tuple[int, ...]
    tab_slots: tuple[int, ...]


@dataclass(frozen=True)
class MapHint:
    map_id: int
    dir_id: int
    romlist: str
    description: str
    is_used: bool


@dataclass(frozen=True)
class ClusterKey:
    key: str
    label: str
    category: str


@dataclass(frozen=True)
class OrigMatch:
    root_file_count: int
    root_files: tuple[str, ...]
    nested_file_count: int
    nested_files: tuple[str, ...]
    named_directory_count: int
    named_directories: tuple[str, ...]
    root_romlist_count: int
    root_romlists: tuple[str, ...]


@dataclass(frozen=True)
class OrigInventory:
    root_counts: dict[str, int]
    root_by_stem: dict[str, tuple[str, ...]]
    nested_counts: dict[str, int]
    nested_by_stem: dict[str, tuple[str, ...]]
    dir_counts: dict[str, int]
    dirs_by_name: dict[str, tuple[str, ...]]
    root_romlist_count: int
    root_romlists: tuple[str, ...]


@dataclass
class Cluster:
    key: str
    labels: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    strings: dict[int, DolString] = field(default_factory=dict)
    xrefs: dict[tuple[int, int, str], StringXref] = field(default_factory=dict)
    neighbor_strings: dict[int, DolString] = field(default_factory=dict)
    orig_match: OrigMatch | None = None
    family_hint: FamilyHint | None = None
    map_hints: tuple[MapHint, ...] = ()

    def direct_xref_count(self) -> int:
        return len(self.xrefs)

    def direct_function_count(self) -> int:
        return len({xref.function_start for xref in self.xrefs.values() if xref.function_start is not None})

    def source_string_count(self) -> int:
        return sum(1 for entry in self.strings.values() if "source" in entry.tags)

    def has_direct_xrefs(self) -> bool:
        return bool(self.xrefs)


class DolFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        section_offsets = [struct.unpack_from(">I", self.data, index * 4)[0] for index in range(18)]
        section_addrs = [struct.unpack_from(">I", self.data, 0x48 + index * 4)[0] for index in range(18)]
        section_sizes = [struct.unpack_from(">I", self.data, 0x90 + index * 4)[0] for index in range(18)]
        self.sections = [
            DolSection(index, section_offsets[index], section_addrs[index], section_sizes[index])
            for index in range(18)
            if section_sizes[index]
        ]
        self.text_sections = [section for section in self.sections if section.index <= 6]

    def offset_to_section(self, offset: int) -> DolSection | None:
        for section in self.sections:
            if section.offset <= offset < section.offset + section.size:
                return section
        return None


def classify_string(text: str) -> tuple[str, ...]:
    tags: list[str] = []
    if SOURCE_TAG_RE.search(text):
        tags.append("source")
    if FILE_TOKEN_RE.search(text):
        tags.append("file")
    if any(token in text for token in ("WARNING", "failed", "overflow", "No Longer supported")):
        tags.append("warning")
    return tuple(tags)


def scan_strings(dol: DolFile) -> list[DolString]:
    strings: list[DolString] = []
    for match in PRINTABLE_RE.finditer(dol.data):
        section = dol.offset_to_section(match.start())
        if section is None:
            continue
        text = match.group().decode("ascii", "ignore")
        tags = classify_string(text)
        if not tags:
            continue
        strings.append(DolString(section.address + (match.start() - section.offset), section.index, text, tags))
    return strings


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
                match.group(1),
                match.group(2),
                int(match.group(3), 16),
                int(match.group(4), 16),
            )
        )
    functions.sort(key=lambda item: item.address)
    return functions


def function_for_address(functions: list[FunctionSymbol], address: int) -> FunctionSymbol | None:
    for function in functions:
        if function.contains(address):
            return function
    return None


def signed_16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def scan_text_xrefs(
    dol: DolFile,
    strings_by_address: dict[int, DolString],
    functions: list[FunctionSymbol],
    window: int = 5,
) -> list[StringXref]:
    results: list[StringXref] = []
    seen: set[tuple[int, int, str]] = set()
    for section in dol.text_sections:
        words = [struct.unpack_from(">I", dol.data, section.offset + rel)[0] for rel in range(0, section.size, 4)]
        for index, first_word in enumerate(words):
            if first_word >> 26 != 15:
                continue
            reg = (first_word >> 21) & 31
            base = (first_word >> 16) & 31
            if base != 0:
                continue
            high_imm = first_word & 0xFFFF
            for next_index in range(index + 1, min(index + window + 1, len(words))):
                second_word = words[next_index]
                opcode = second_word >> 26
                second_base = (second_word >> 16) & 31
                candidate: int | None = None
                pair_kind: str | None = None
                if opcode == 14 and second_base == reg:
                    candidate = ((signed_16(high_imm) << 16) + signed_16(second_word & 0xFFFF)) & 0xFFFFFFFF
                    pair_kind = "lis/addi"
                elif opcode == 24 and second_base == reg and ((second_word >> 21) & 31) == reg:
                    candidate = ((high_imm << 16) | (second_word & 0xFFFF)) & 0xFFFFFFFF
                    pair_kind = "lis/ori"
                if candidate is None:
                    continue
                string_entry = strings_by_address.get(candidate)
                if string_entry is None:
                    continue
                xref_address = section.address + (index * 4)
                key = (xref_address, candidate, pair_kind)
                if key in seen:
                    continue
                seen.add(key)
                function = function_for_address(functions, xref_address)
                results.append(
                    StringXref(
                        xref_address,
                        section.address + (next_index * 4),
                        candidate,
                        string_entry.text,
                        pair_kind,
                        None if function is None else function.name,
                        None if function is None else function.address,
                    )
                )
    results.sort(key=lambda item: (item.target_address, item.xref_address))
    return results


def build_neighbor_lookup(strings: list[DolString]) -> dict[int, list[DolString]]:
    by_section: dict[int, list[DolString]] = defaultdict(list)
    for entry in strings:
        by_section[entry.section_index].append(entry)
    for values in by_section.values():
        values.sort(key=lambda item: item.address)
    return by_section


def neighbor_context(entry: DolString, by_section: dict[int, list[DolString]], radius: int = 1) -> list[DolString]:
    values = by_section[entry.section_index]
    index = values.index(entry)
    start = max(0, index - radius)
    end = min(len(values), index + radius + 1)
    return [item for item in values[start:end] if item.address != entry.address]


def group_xrefs_by_target(xrefs: list[StringXref]) -> dict[int, list[StringXref]]:
    grouped: dict[int, list[StringXref]] = defaultdict(list)
    for entry in xrefs:
        grouped[entry.target_address].append(entry)
    return grouped


def slugify(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value or "xref"


def parse_slot_tuple(raw: str) -> tuple[int, ...]:
    return tuple(int(value, 16) for value in re.findall(r"0x([0-9A-Fa-f]+)", raw))


def load_family_hints(reference: Path) -> dict[str, FamilyHint]:
    if not reference.is_file():
        return {}
    hints: dict[str, FamilyHint] = {}
    for line in reference.read_text(encoding="utf-8", errors="replace").splitlines():
        match = FILE_TABLE_ENTRY_RE.match(line)
        if match is None:
            continue
        family = match.group(1).upper()
        hints[family] = FamilyHint(family, parse_slot_tuple(match.group(2)), parse_slot_tuple(match.group(3)))
    return hints


def load_map_hints(reference: Path) -> dict[str, tuple[MapHint, ...]]:
    if not reference.is_file():
        return {}
    root = ET.fromstring(reference.read_text(encoding="utf-8", errors="replace"))
    hints: dict[str, list[MapHint]] = defaultdict(list)
    for element in root.findall(".//{*}map"):
        romlist = element.get("romlist")
        map_id = element.get("id")
        dir_id = element.get("dirid")
        if romlist is None or map_id is None or dir_id is None:
            continue
        description = (element.findtext("{*}description") or "").strip()
        hint = MapHint(
            int(map_id, 16),
            int(dir_id, 16),
            romlist,
            description,
            element.get("isused") == "1",
        )
        hints[slugify(romlist)].append(hint)
    return {
        key: tuple(sorted(values, key=lambda item: (not item.is_used, item.map_id)))
        for key, values in hints.items()
    }


def format_slots(values: tuple[int, ...]) -> str:
    return "none" if not values else ", ".join(f"0x{value:02X}" for value in values)


def extract_source_keys(text: str) -> list[ClusterKey]:
    keys: list[ClusterKey] = []
    seen: set[str] = set()
    for match in SOURCE_TAG_RE.finditer(text):
        tag = Path(match.group(0)).name
        stem = Path(tag).stem
        key = slugify(stem)
        if key in seen:
            continue
        seen.add(key)
        keys.append(ClusterKey(key, tag, "source"))
    return keys


def extract_file_keys(text: str) -> list[ClusterKey]:
    keys: list[ClusterKey] = []
    seen: set[str] = set()
    for match in FILE_TOKEN_RE.finditer(text):
        token = match.group(0).replace("\\", "/").lstrip("/")
        lower = token.lower()
        key: str | None = None
        label = token
        if lower.endswith(".romlist.zlb"):
            key = "romlist"
            label = ".romlist.zlb"
        elif "/" in token:
            first = token.split("/", 1)[0]
            if "%" not in first:
                key = slugify(first)
                label = first
        else:
            stem = Path(token).name.split(".", 1)[0]
            if "%" not in stem:
                key = slugify(stem)
                label = Path(token).name
        if key is None or key in seen:
            continue
        seen.add(key)
        keys.append(ClusterKey(key, label, "file"))
    return keys


def cluster_keys_for_string(entry: DolString) -> list[ClusterKey]:
    by_key = {item.key: item for item in extract_source_keys(entry.text)}
    for item in extract_file_keys(entry.text):
        by_key.setdefault(item.key, item)
    return list(by_key.values())


def build_orig_inventory(files_root: Path) -> OrigInventory:
    root_by_stem: dict[str, list[str]] = defaultdict(list)
    nested_by_stem: dict[str, list[str]] = defaultdict(list)
    dirs_by_name: dict[str, list[str]] = defaultdict(list)
    root_romlists: list[str] = []
    for path in sorted(files_root.iterdir()):
        if path.is_file():
            root_by_stem[path.stem.upper()].append(path.name)
            if path.suffix.lower() == ".zlb" and path.name.lower().endswith(".romlist.zlb"):
                root_romlists.append(path.name)
        elif path.is_dir():
            dirs_by_name[path.name.lower()].append(path.relative_to(files_root).as_posix())
    for path in sorted(files_root.rglob("*")):
        if not path.is_file() or path.parent == files_root:
            continue
        nested_by_stem[path.stem.upper()].append(path.relative_to(files_root).as_posix())
    return OrigInventory(
        root_counts={key: len(value) for key, value in root_by_stem.items()},
        root_by_stem={key: tuple(value[:12]) for key, value in root_by_stem.items()},
        nested_counts={key: len(value) for key, value in nested_by_stem.items()},
        nested_by_stem={key: tuple(value[:12]) for key, value in nested_by_stem.items()},
        dir_counts={key: len(value) for key, value in dirs_by_name.items()},
        dirs_by_name={key: tuple(value[:12]) for key, value in dirs_by_name.items()},
        root_romlist_count=len(root_romlists),
        root_romlists=tuple(root_romlists[:16]),
    )


def orig_matches_for_key(inventory: OrigInventory, key: str) -> OrigMatch:
    return OrigMatch(
        inventory.root_counts.get(key.upper(), 0),
        inventory.root_by_stem.get(key.upper(), ()),
        inventory.nested_counts.get(key.upper(), 0),
        inventory.nested_by_stem.get(key.upper(), ()),
        inventory.dir_counts.get(key.lower(), 0),
        inventory.dirs_by_name.get(key.lower(), ()),
        inventory.root_romlist_count if key == "romlist" else 0,
        inventory.root_romlists if key == "romlist" else (),
    )


def cluster_sort_key(cluster: Cluster) -> tuple[int, int, int, int, str]:
    match = cluster.orig_match
    orig_score = 0
    if match is not None:
        orig_score = sum(bool(item) for item in (match.root_files, match.nested_files, match.named_directories, match.root_romlists))
    return (
        cluster.direct_function_count(),
        cluster.direct_xref_count(),
        cluster.source_string_count(),
        orig_score,
        cluster.key,
    )


def build_clusters(
    strings: list[DolString],
    xrefs: list[StringXref],
    inventory: OrigInventory,
    family_hints: dict[str, FamilyHint],
    map_hints: dict[str, tuple[MapHint, ...]],
) -> list[Cluster]:
    grouped_xrefs = group_xrefs_by_target(xrefs)
    neighbors = build_neighbor_lookup(strings)
    clusters: dict[str, Cluster] = {}
    for entry in strings:
        keys = cluster_keys_for_string(entry)
        if not keys:
            continue
        xref_group = grouped_xrefs.get(entry.address, [])
        if not xref_group and "source" not in entry.tags:
            continue
        for key in keys:
            cluster = clusters.setdefault(key.key, Cluster(key=key.key))
            cluster.labels.add(key.label)
            cluster.categories.add(key.category)
            cluster.strings.setdefault(entry.address, entry)
            if cluster.orig_match is None:
                cluster.orig_match = orig_matches_for_key(inventory, key.key)
            family_hint = family_hints.get(key.key.upper())
            if family_hint is not None:
                cluster.family_hint = family_hint
            if not cluster.map_hints:
                cluster.map_hints = map_hints.get(key.key, ())
            for xref in xref_group:
                cluster.xrefs[(xref.xref_address, xref.target_address, xref.pair_kind)] = xref
            for neighbor in neighbor_context(entry, neighbors):
                neighbor_keys = {item.key for item in cluster_keys_for_string(neighbor)}
                if key.key in neighbor_keys or not xref_group:
                    if neighbor.address not in cluster.strings:
                        cluster.neighbor_strings.setdefault(neighbor.address, neighbor)
    visible = [cluster for cluster in clusters.values() if cluster.has_direct_xrefs() or cluster.source_string_count() > 0]
    visible.sort(key=cluster_sort_key, reverse=True)
    return visible


def summarize_orig_match(match: OrigMatch | None) -> str:
    if match is None:
        return "none"
    parts: list[str] = []
    if match.root_file_count:
        parts.append(f"root files={match.root_file_count}")
    if match.nested_file_count:
        parts.append(f"nested matches={match.nested_file_count}")
    if match.named_directory_count:
        parts.append(f"dirs={match.named_directory_count}")
    if match.root_romlist_count:
        parts.append(f"root romlists={match.root_romlist_count}")
    return ", ".join(parts) if parts else "none"


def summarize_map_hints(values: tuple[MapHint, ...]) -> str:
    if not values:
        return "none"
    used = [item for item in values if item.is_used]
    target = used if used else list(values)
    preview = ", ".join(item.romlist for item in target[:3])
    if len(target) > 3:
        preview += ", ..."
    return preview


def format_function_name(xref: StringXref) -> str:
    if xref.function_name is None or xref.function_start is None:
        return "unknown"
    offset = xref.xref_address - xref.function_start
    return xref.function_name if offset == 0 else f"{xref.function_name}+0x{offset:X}"


def unique_functions(cluster: Cluster) -> list[tuple[int | None, str, list[StringXref]]]:
    by_function: dict[int | None, list[StringXref]] = defaultdict(list)
    for xref in cluster.xrefs.values():
        by_function[xref.function_start].append(xref)
    items: list[tuple[int | None, str, list[StringXref]]] = []
    for function_start, group in by_function.items():
        group.sort(key=lambda item: item.xref_address)
        items.append((function_start, format_function_name(group[0]).split("+", 1)[0], group))
    items.sort(key=lambda item: (item[0] is None, item[0] or 0))
    return items


def summary_markdown(clusters: list[Cluster], limit: int) -> str:
    direct = [cluster for cluster in clusters if cluster.has_direct_xrefs()]
    source_only = [cluster for cluster in clusters if not cluster.has_direct_xrefs() and cluster.source_string_count() > 0]
    orig_backed = [cluster for cluster in clusters if summarize_orig_match(cluster.orig_match) != "none"]
    map_backed = [cluster for cluster in clusters if cluster.map_hints]
    lines: list[str] = []
    lines.append("# Asset xref clusters")
    lines.append("")
    lines.append(f"- Visible clusters: {len(clusters)}")
    lines.append(f"- Clusters with direct code xrefs: {len(direct)}")
    lines.append(f"- Source-only context clusters: {len(source_only)}")
    lines.append(f"- Clusters with direct `orig/files` matches: {len(orig_backed)}")
    lines.append(f"- Clusters with map/romlist hints: {len(map_backed)}")
    lines.append("")
    lines.append("## Best immediate packets")
    for cluster in clusters[:limit]:
        categories = ", ".join(sorted(cluster.categories))
        lines.append(
            f"- `{cluster.key}` ({categories}): "
            f"{cluster.direct_xref_count()} direct xrefs across {cluster.direct_function_count()} functions; "
            f"orig={summarize_orig_match(cluster.orig_match)}; maps={summarize_map_hints(cluster.map_hints)}"
        )
    lines.append("")
    lines.append("## Usage")
    lines.append("- Summary: `python tools/xref/asset_clusters.py`")
    lines.append("- Search packets: `python tools/xref/asset_clusters.py --search romlist camcontrol savegame`")
    lines.append("- CSV dump: `python tools/xref/asset_clusters.py --format csv`")
    lines.append("- Materialize `src/xref` + `docs/xref`: `python tools/xref/asset_clusters.py --materialize-all`")
    return "\n".join(lines)


def cluster_matches(cluster: Cluster, patterns: list[str]) -> bool:
    lowered = [pattern.lower() for pattern in patterns]
    haystacks = [
        cluster.key.lower(),
        " ".join(sorted(cluster.labels)).lower(),
        " ".join(sorted(cluster.categories)).lower(),
        summarize_orig_match(cluster.orig_match).lower(),
        summarize_map_hints(cluster.map_hints).lower(),
    ]
    if cluster.family_hint is not None:
        haystacks.append(cluster.family_hint.family.lower())
    for item in cluster.map_hints:
        haystacks.append(item.romlist.lower())
        if item.description:
            haystacks.append(item.description.lower())
    for entry in cluster.strings.values():
        haystacks.append(entry.text.lower())
    return any(any(pattern in item for item in haystacks) for pattern in lowered)


def search_markdown(clusters: list[Cluster], patterns: list[str], limit: int) -> str:
    matches = [cluster for cluster in clusters if cluster_matches(cluster, patterns)]
    lines: list[str] = []
    lines.append("# Asset xref search")
    lines.append("")
    if not matches:
        lines.append("- No matching clusters.")
        return "\n".join(lines)
    for cluster in matches[:limit]:
        lines.append(
            f"- `{cluster.key}`: {cluster.direct_xref_count()} xrefs, "
            f"{cluster.direct_function_count()} functions, "
            f"orig={summarize_orig_match(cluster.orig_match)}, maps={summarize_map_hints(cluster.map_hints)}"
        )
        for function_start, name, group in unique_functions(cluster):
            address_text = "unknown" if function_start is None else f"0x{function_start:08X}"
            preview = "; ".join(f"`{xref.target_text}`" for xref in group[:2])
            lines.append(f"  - `{address_text}` `{name}` -> {preview}")
    return "\n".join(lines)


def rows_to_csv(clusters: list[Cluster]) -> str:
    fieldnames = [
        "key",
        "labels",
        "categories",
        "direct_xrefs",
        "direct_functions",
        "source_strings",
        "orig_summary",
        "map_summary",
        "family_slots_bin",
        "family_slots_tab",
        "packet_path",
        "doc_path",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for cluster in clusters:
        writer.writerow(
            {
                "key": cluster.key,
                "labels": " | ".join(sorted(cluster.labels)),
                "categories": " | ".join(sorted(cluster.categories)),
                "direct_xrefs": cluster.direct_xref_count(),
                "direct_functions": cluster.direct_function_count(),
                "source_strings": cluster.source_string_count(),
                "orig_summary": summarize_orig_match(cluster.orig_match),
                "map_summary": summarize_map_hints(cluster.map_hints),
                "family_slots_bin": "" if cluster.family_hint is None else format_slots(cluster.family_hint.bin_slots),
                "family_slots_tab": "" if cluster.family_hint is None else format_slots(cluster.family_hint.tab_slots),
                "packet_path": f"src/xref/packets/{cluster.key}.json",
                "doc_path": f"docs/xref/packets/{cluster.key}.md",
            }
        )
    return buffer.getvalue()


def data_packet_path(output_root: Path, cluster: Cluster) -> Path:
    return output_root / "packets" / f"{cluster.key}.json"


def doc_packet_path(output_root: Path, cluster: Cluster) -> Path:
    return output_root / "packets" / f"{cluster.key}.md"


def packet_payload(cluster: Cluster) -> dict[str, object]:
    neighbor_strings = [
        entry
        for entry in sorted(cluster.neighbor_strings.values(), key=lambda item: item.address)
        if entry.address not in cluster.strings
    ]
    return {
        "key": cluster.key,
        "labels": sorted(cluster.labels),
        "categories": sorted(cluster.categories),
        "direct_xref_count": cluster.direct_xref_count(),
        "direct_function_count": cluster.direct_function_count(),
        "source_string_count": cluster.source_string_count(),
        "orig": {
            "root_file_count": 0 if cluster.orig_match is None else cluster.orig_match.root_file_count,
            "root_files": list(cluster.orig_match.root_files) if cluster.orig_match else [],
            "nested_file_count": 0 if cluster.orig_match is None else cluster.orig_match.nested_file_count,
            "nested_files": list(cluster.orig_match.nested_files) if cluster.orig_match else [],
            "named_directory_count": 0 if cluster.orig_match is None else cluster.orig_match.named_directory_count,
            "named_directories": list(cluster.orig_match.named_directories) if cluster.orig_match else [],
            "root_romlist_count": 0 if cluster.orig_match is None else cluster.orig_match.root_romlist_count,
            "root_romlists": list(cluster.orig_match.root_romlists) if cluster.orig_match else [],
        },
        "family_hint": None
        if cluster.family_hint is None
        else {
            "family": cluster.family_hint.family,
            "bin_slots": list(cluster.family_hint.bin_slots),
            "tab_slots": list(cluster.family_hint.tab_slots),
        },
        "map_hints": [
            {
                "map_id": f"0x{item.map_id:02X}",
                "dir_id": f"0x{item.dir_id:02X}",
                "romlist": item.romlist,
                "description": item.description,
                "is_used": item.is_used,
            }
            for item in cluster.map_hints
        ],
        "functions": [
            {
                "function_start": None if function_start is None else f"0x{function_start:08X}",
                "function_name": name,
                "xrefs": [
                    {
                        "xref_address": f"0x{xref.xref_address:08X}",
                        "pair_address": f"0x{xref.pair_address:08X}",
                        "target_address": f"0x{xref.target_address:08X}",
                        "target_text": xref.target_text,
                        "pair_kind": xref.pair_kind,
                        "function_name": xref.function_name,
                    }
                    for xref in group
                ],
            }
            for function_start, name, group in unique_functions(cluster)
        ],
        "strings": [
            {
                "address": f"0x{entry.address:08X}",
                "text": entry.text,
                "tags": list(entry.tags),
            }
            for entry in sorted(cluster.strings.values(), key=lambda item: item.address)
        ],
        "neighbor_strings": [
            {
                "address": f"0x{entry.address:08X}",
                "text": entry.text,
                "tags": list(entry.tags),
            }
            for entry in neighbor_strings
        ],
    }


def packet_text(cluster: Cluster, data_root: Path, docs_root: Path) -> str:
    neighbor_strings = [
        entry
        for entry in sorted(cluster.neighbor_strings.values(), key=lambda item: item.address)
        if entry.address not in cluster.strings
    ]
    lines: list[str] = []
    lines.append(f"# `{cluster.key}`")
    lines.append("")
    lines.append("Auto-generated by `python tools/xref/asset_clusters.py --materialize-all`.")
    lines.append("")
    lines.append("## Signal")
    lines.append(f"- Labels: {', '.join(f'`{label}`' for label in sorted(cluster.labels))}")
    lines.append(f"- Categories: {', '.join(f'`{category}`' for category in sorted(cluster.categories))}")
    lines.append(f"- Direct text xrefs: {cluster.direct_xref_count()}")
    lines.append(f"- Direct functions: {cluster.direct_function_count()}")
    lines.append(f"- Source strings: {cluster.source_string_count()}")
    lines.append(f"- Data packet: `src/xref/packets/{data_packet_path(data_root, cluster).name}`")
    lines.append(f"- Doc packet: `docs/xref/packets/{doc_packet_path(docs_root, cluster).name}`")
    lines.append("")
    lines.append("## Current EN code xrefs")
    if cluster.xrefs:
        for function_start, name, group in unique_functions(cluster):
            lines.append(f"- `{'unknown' if function_start is None else f'0x{function_start:08X}'}` `{name}`")
            for xref in group:
                lines.append(
                    f"  - xref `0x{xref.xref_address:08X}` via `{xref.pair_kind}` -> "
                    f"`0x{xref.target_address:08X}` `{xref.target_text}`"
                )
    else:
        lines.append("- No direct `lis`/`addi` or `lis`/`ori` xrefs; keep this packet for source-tag context only.")
    lines.append("")
    lines.append("## Retail strings")
    for entry in sorted(cluster.strings.values(), key=lambda item: item.address):
        lines.append(f"- `0x{entry.address:08X}` `{entry.text}` ({', '.join(entry.tags)})")
    if neighbor_strings:
        lines.append("")
        lines.append("## Nearby retail strings")
        for entry in neighbor_strings:
            lines.append(f"- `0x{entry.address:08X}` `{entry.text}` ({', '.join(entry.tags)})")
    lines.append("")
    lines.append("## `orig/files` matches")
    match = cluster.orig_match
    if match is None or not any((match.root_files, match.nested_files, match.named_directories, match.root_romlists)):
        lines.append("- No direct filename or directory match under `orig/GSAE01/files`.")
    else:
        if match.root_files:
            lines.append(
                f"- Root files ({match.root_file_count}): {', '.join(f'`{item}`' for item in match.root_files)}"
            )
        if match.nested_files:
            lines.append(
                f"- Nested matches ({match.nested_file_count}): {', '.join(f'`{item}`' for item in match.nested_files)}"
            )
        if match.named_directories:
            lines.append(
                f"- Named directories ({match.named_directory_count}): {', '.join(f'`{item}`' for item in match.named_directories)}"
            )
        if match.root_romlists:
            lines.append(
                f"- Root romlist samples ({match.root_romlist_count} total): "
                + ", ".join(f'`{item}`' for item in match.root_romlists)
            )
    lines.append("")
    lines.append("## Reference overlays")
    if cluster.family_hint is None:
        lines.append("- No direct `fileTable` family hint from `reference_projects/rena-tools/StarFoxAdventures/debugger/game.py`.")
    else:
        lines.append(f"- Family: `{cluster.family_hint.family}`")
        lines.append(f"- `bin` slots: {format_slots(cluster.family_hint.bin_slots)}")
        lines.append(f"- `tab` slots: {format_slots(cluster.family_hint.tab_slots)}")
    if cluster.map_hints:
        for item in cluster.map_hints[:8]:
            description = "" if not item.description else f" {item.description}"
            used = "used" if item.is_used else "unused"
            lines.append(
                f"- Map `0x{item.map_id:02X}` dir `0x{item.dir_id:02X}` `{item.romlist}` ({used}){description}"
            )
    else:
        lines.append("- No direct romlist alias match from `reference_projects/rena-tools/SFA-Browser/data/U0/maps.xml`.")
    lines.append("")
    lines.append("## Regenerate")
    lines.append("- `python tools/xref/asset_clusters.py --materialize-all`")
    return "\n".join(lines)


def index_json(clusters: list[Cluster]) -> str:
    payload = {
        "generated_by": "python tools/xref/asset_clusters.py --materialize-all",
        "cluster_count": len(clusters),
        "clusters": [
            {
                "key": cluster.key,
                "labels": sorted(cluster.labels),
                "categories": sorted(cluster.categories),
                "direct_xref_count": cluster.direct_xref_count(),
                "direct_function_count": cluster.direct_function_count(),
                "source_string_count": cluster.source_string_count(),
                "packet_path": f"src/xref/packets/{cluster.key}.json",
                "doc_path": f"docs/xref/packets/{cluster.key}.md",
                "orig_summary": summarize_orig_match(cluster.orig_match),
                "map_summary": summarize_map_hints(cluster.map_hints),
                "top_strings": [entry.text for entry in sorted(cluster.strings.values(), key=lambda item: item.address)[:3]],
            }
            for cluster in clusters
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def readme_text(clusters: list[Cluster], data_root: Path, docs_root: Path) -> str:
    manifest_rel = Path(os.path.relpath(data_root / "index.json", docs_root)).as_posix()
    lines: list[str] = []
    lines.append("# Asset Xref Packets")
    lines.append("")
    lines.append("Generated xref packets linking retail EN DOL string loads to current EN functions, `orig/files` assets, runtime file-family hints, and romlist/map aliases.")
    lines.append("")
    lines.append("## Regenerate")
    lines.append("- `python tools/xref/asset_clusters.py --materialize-all`")
    lines.append("")
    lines.append("## Top packets")
    for cluster in clusters[:20]:
        rel = doc_packet_path(docs_root, cluster).relative_to(docs_root).as_posix()
        lines.append(
            f"- [{cluster.key}]({rel}): "
            f"{cluster.direct_xref_count()} xrefs, {cluster.direct_function_count()} functions, "
            f"orig={summarize_orig_match(cluster.orig_match)}, maps={summarize_map_hints(cluster.map_hints)}"
        )
    lines.append("")
    lines.append("## Machine Data")
    lines.append(f"- [src/xref/index.json]({manifest_rel})")
    return "\n".join(lines) + "\n"


def materialize(clusters: list[Cluster], output_root: Path, docs_root: Path, limit: int | None) -> list[Path]:
    selected = clusters if limit is None else clusters[:limit]
    packets_root = output_root / "packets"
    doc_packets_root = docs_root / "packets"
    output_root.mkdir(parents=True, exist_ok=True)
    docs_root.mkdir(parents=True, exist_ok=True)
    packets_root.mkdir(parents=True, exist_ok=True)
    doc_packets_root.mkdir(parents=True, exist_ok=True)
    for path in packets_root.glob("*"):
        if path.is_file():
            path.unlink()
    for path in doc_packets_root.glob("*.md"):
        path.unlink()
    readme_path = output_root / "README.md"
    if readme_path.exists():
        readme_path.unlink()
    written: list[Path] = []
    for cluster in selected:
        payload_path = data_packet_path(output_root, cluster)
        payload_path.write_text(json.dumps(packet_payload(cluster), indent=2) + "\n", encoding="utf-8")
        doc_path = doc_packet_path(docs_root, cluster)
        doc_path.write_text(packet_text(cluster, output_root, docs_root), encoding="utf-8")
        written.append(payload_path)
    (output_root / "index.json").write_text(index_json(selected), encoding="utf-8")
    (docs_root / "README.md").write_text(readme_text(selected, output_root, docs_root), encoding="utf-8")
    return written


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cluster retail EN DOL string xrefs against orig/files asset names, file-family hints, and map aliases."
    )
    parser.add_argument("--dol", type=Path, default=Path("orig/GSAE01/sys/main.dol"), help="Path to the EN main.dol.")
    parser.add_argument(
        "--symbols",
        type=Path,
        default=Path("config/GSAE01/symbols.txt"),
        help="symbols.txt used to name containing functions.",
    )
    parser.add_argument(
        "--files-root",
        type=Path,
        default=Path("orig/GSAE01/files"),
        help="Path to the extracted EN files/ directory.",
    )
    parser.add_argument(
        "--family-reference",
        type=Path,
        default=Path("reference_projects/rena-tools/StarFoxAdventures/debugger/game.py"),
        help="Reference `fileTable` source used for family slot hints.",
    )
    parser.add_argument(
        "--maps-reference",
        type=Path,
        default=Path("reference_projects/rena-tools/SFA-Browser/data/U0/maps.xml"),
        help="Reference map/romlist alias source used for map hints.",
    )
    parser.add_argument("--format", choices=("markdown", "csv", "json"), default="markdown", help="Output format.")
    parser.add_argument("--search", nargs="+", help="Case-insensitive search over cluster keys, labels, and strings.")
    parser.add_argument("--limit", type=int, default=15, help="Maximum clusters to show in summary or search mode.")
    parser.add_argument("--materialize-top", type=int, help="Write the top N packets under --output-root.")
    parser.add_argument("--materialize-all", action="store_true", help="Write every visible packet.")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("src/xref"),
        help="Destination directory for machine-readable xref packets.",
    )
    parser.add_argument(
        "--docs-root",
        type=Path,
        default=Path("docs/xref"),
        help="Destination directory for generated markdown packet docs.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    dol = DolFile(args.dol.resolve())
    strings = scan_strings(dol)
    functions = load_function_symbols(args.symbols.resolve())
    strings_by_address = {entry.address: entry for entry in strings}
    xrefs = scan_text_xrefs(dol, strings_by_address, functions)
    family_hints = load_family_hints(args.family_reference.resolve())
    map_hints = load_map_hints(args.maps_reference.resolve())
    inventory = build_orig_inventory(args.files_root.resolve())
    clusters = build_clusters(strings, xrefs, inventory, family_hints, map_hints)

    visible = clusters
    if args.search:
        visible = [cluster for cluster in clusters if cluster_matches(cluster, args.search)]

    if args.materialize_all:
        materialize(visible, args.output_root.resolve(), args.docs_root.resolve(), limit=None)
    elif args.materialize_top:
        materialize(visible, args.output_root.resolve(), args.docs_root.resolve(), limit=args.materialize_top)

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(visible))
        elif args.format == "json":
            sys.stdout.write(index_json(visible))
        elif args.search:
            sys.stdout.write(search_markdown(visible, args.search, args.limit))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(visible, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
