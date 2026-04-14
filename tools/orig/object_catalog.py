from __future__ import annotations

import argparse
import csv
import io
import struct
import sys
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


FIELD_SPECS = (
    ("pModelList", 0x08),
    ("field_0x18", 0x18),
    ("pSeq", 0x1C),
    ("pEvent", 0x20),
    ("pHits", 0x24),
    ("pWeaponDa", 0x28),
    ("hitboxes", 0x2C),
    ("aButtonInteraction", 0x40),
)


@dataclass(frozen=True)
class ObjectRecord:
    def_id: int
    offset: int
    size: int
    name: str
    remap_target: int
    remap_sources: tuple[int, ...]
    placements: int
    romlists: int
    dll_id: int
    class_id: int
    n_models: int
    n_player_objs: int
    n_sequences: int
    map_id: int
    map_name: str | None
    model_ids: tuple[int, ...]
    sequence_ids: tuple[int, ...]
    help_texts: tuple[int, ...]
    inline_fields: tuple[str, ...]
    field_values: tuple[tuple[str, int], ...]


def load_object_offsets(tab_path: Path) -> tuple[list[int], list[int]]:
    data = tab_path.read_bytes()
    raw_offsets: list[int] = []
    for offset in range(0, len(data), 4):
        value = struct.unpack_from(">I", data, offset)[0]
        if value == 0xFFFFFFFF:
            break
        raw_offsets.append(value)

    if len(raw_offsets) < 2:
        raise ValueError("OBJECTS.tab did not contain enough offsets to recover any records")
    return raw_offsets[:-1], raw_offsets


def load_objindex(path: Path) -> list[int]:
    data = path.read_bytes()
    if len(data) % 2 != 0:
        raise ValueError(f"Unexpected OBJINDEX.bin size: {len(data)}")
    return [struct.unpack_from(">h", data, offset)[0] for offset in range(0, len(data), 2)]


def load_map_names(path: Path) -> list[str]:
    data = path.read_bytes()
    if len(data) % 0x20 != 0:
        raise ValueError(f"Unexpected MAPINFO.bin size: {len(data)}")
    names: list[str] = []
    for offset in range(0, len(data), 0x20):
        raw_name = data[offset : offset + 28]
        names.append(raw_name.split(b"\0", 1)[0].decode("ascii", "replace"))
    return names


def resolve_object_id(objindex: list[int], object_id: int) -> int:
    if 0 <= object_id < len(objindex):
        remapped = objindex[object_id]
        if remapped != -1:
            return remapped
    return object_id


def decompress_zlb(path: Path) -> bytes:
    data = path.read_bytes()
    if data[:4] != b"ZLB\0":
        raise ValueError(f"Unsupported container in {path}")
    version, decompressed_size, compressed_size = struct.unpack_from(">3I", data, 4)
    if version != 1:
        raise ValueError(f"Unexpected ZLB version {version} in {path}")
    payload = zlib.decompress(data[16 : 16 + compressed_size])
    if len(payload) != decompressed_size:
        raise ValueError(f"Bad ZLB size in {path}: expected {decompressed_size}, got {len(payload)}")
    return payload


def load_romlist_usage(files_root: Path, objindex: list[int]) -> tuple[Counter[int], dict[int, set[str]]]:
    placements: Counter[int] = Counter()
    romlists_by_def: dict[int, set[str]] = defaultdict(set)
    for romlist_path in sorted(files_root.glob("*.romlist.zlb")):
        payload = decompress_zlb(romlist_path)
        offset = 0
        while offset < len(payload):
            object_id, size_words, _flags = struct.unpack_from(">hBB", payload, offset)
            record_size = size_words * 4
            if record_size <= 0 or offset + record_size > len(payload):
                raise ValueError(
                    f"Invalid record in {romlist_path.name}: offset=0x{offset:X} size_words={size_words}"
                )
            canonical_id = resolve_object_id(objindex, object_id)
            placements[canonical_id] += 1
            romlists_by_def[canonical_id].add(romlist_path.name)
            offset += record_size
    return placements, romlists_by_def


def build_reverse_remap(objindex: list[int], object_count: int) -> dict[int, list[int]]:
    reverse: dict[int, list[int]] = defaultdict(list)
    for object_id in range(len(objindex)):
        canonical_id = resolve_object_id(objindex, object_id)
        if 0 <= canonical_id < object_count and canonical_id != object_id:
            reverse[canonical_id].append(object_id)
    return {key: sorted(values) for key, values in reverse.items()}


def read_inline_u16s(blob: bytes, record_offset: int, rel_offset: int, count: int) -> tuple[int, ...]:
    start = record_offset + rel_offset
    if count <= 0:
        return ()
    return tuple(struct.unpack_from(f">{count}H", blob, start))


def read_inline_u32s(blob: bytes, record_offset: int, rel_offset: int, count: int) -> tuple[int, ...]:
    start = record_offset + rel_offset
    if count <= 0:
        return ()
    return tuple(struct.unpack_from(f">{count}I", blob, start))


def build_records(
    files_root: Path,
    placements: Counter[int],
    romlists_by_def: dict[int, set[str]],
) -> tuple[list[ObjectRecord], list[int]]:
    object_bin = (files_root / "OBJECTS.bin").read_bytes()
    offsets, raw_offsets = load_object_offsets(files_root / "OBJECTS.tab")
    objindex = load_objindex(files_root / "OBJINDEX.bin")
    map_names = load_map_names(files_root / "MAPINFO.bin")
    reverse_remap = build_reverse_remap(objindex, len(offsets))

    records: list[ObjectRecord] = []
    for def_id, (offset, next_offset) in enumerate(zip(offsets, raw_offsets[1:])):
        size = next_offset - offset
        name = object_bin[offset + 0x91 : offset + 0x9C].split(b"\0", 1)[0].decode("ascii", "replace")
        dll_id, class_id = struct.unpack_from(">Hh", object_bin, offset + 0x50)
        n_models, n_player_objs = struct.unpack_from(">BB", object_bin, offset + 0x55)
        n_sequences = object_bin[offset + 0x5E]
        map_id = struct.unpack_from(">H", object_bin, offset + 0x78)[0]
        map_name = None if map_id == 0xFFFF or map_id >= len(map_names) else map_names[map_id]
        help_texts = struct.unpack_from(">4H", object_bin, offset + 0x7C)

        field_values = [(name_text, struct.unpack_from(">I", object_bin, offset + field_offset)[0]) for name_text, field_offset in FIELD_SPECS]
        inline_fields = tuple(
            name_text
            for name_text, value in field_values
            if value != 0 and offset <= offset + value < next_offset
        )

        p_model_list = dict(field_values)["pModelList"]
        if offset <= offset + p_model_list < next_offset:
            model_ids = read_inline_u32s(object_bin, offset, p_model_list, n_models)
        else:
            model_ids = ()

        p_seq = dict(field_values)["pSeq"]
        if p_seq != 0 and offset <= offset + p_seq < next_offset:
            sequence_ids = read_inline_u16s(object_bin, offset, p_seq, n_sequences)
        else:
            sequence_ids = ()

        records.append(
            ObjectRecord(
                def_id=def_id,
                offset=offset,
                size=size,
                name=name,
                remap_target=resolve_object_id(objindex, def_id),
                remap_sources=tuple(reverse_remap.get(def_id, [])),
                placements=placements.get(def_id, 0),
                romlists=len(romlists_by_def.get(def_id, set())),
                dll_id=dll_id,
                class_id=class_id,
                n_models=n_models,
                n_player_objs=n_player_objs,
                n_sequences=n_sequences,
                map_id=map_id,
                map_name=map_name,
                model_ids=model_ids,
                sequence_ids=sequence_ids,
                help_texts=help_texts,
                inline_fields=inline_fields,
                field_values=tuple(field_values),
            )
        )
    return records, raw_offsets


def format_hex_list(values: tuple[int, ...]) -> str:
    if not values:
        return ""
    return " ".join(f"0x{value:04X}" for value in values)


def summarize_groups(
    records: list[ObjectRecord],
    key_fn,
) -> list[tuple[int, int, int, list[ObjectRecord]]]:
    by_key: dict[int, list[ObjectRecord]] = defaultdict(list)
    for record in records:
        by_key[key_fn(record)].append(record)

    groups: list[tuple[int, int, int, list[ObjectRecord]]] = []
    for key, items in by_key.items():
        placements = sum(item.placements for item in items)
        groups.append((key, placements, len(items), sorted(items, key=lambda item: (-item.placements, item.def_id))))
    groups.sort(key=lambda item: (-item[1], -item[2], item[0]))
    return groups


def summary_markdown(records: list[ObjectRecord], raw_offsets: list[int], objindex: list[int]) -> str:
    span_counter = Counter(record.size for record in records)
    field_inline_counts = Counter(field for record in records for field in record.inline_fields)
    remap_targets = Counter(resolve_object_id(objindex, object_id) for object_id in range(len(objindex)))

    dll_groups = summarize_groups(records, lambda record: record.dll_id)
    class_groups = summarize_groups(records, lambda record: record.class_id)
    fixed_map_groups = summarize_groups(
        [record for record in records if record.map_id != 0xFFFF and record.map_name is not None],
        lambda record: record.map_id,
    )

    remapped_record_count = sum(1 for record in records if record.remap_target != record.def_id)
    unique_targets_within_defs = len({resolve_object_id(objindex, object_id) for object_id in range(len(records))})

    lines: list[str] = []
    lines.append("# `orig/GSAE01/files/OBJECTS.*` catalog")
    lines.append("")
    lines.append("## Summary")
    lines.append(
        f"- `OBJECTS.tab` entries before `0xFFFFFFFF`: {len(raw_offsets)} "
        f"({len(records)} real object defs plus one EOF offset)"
    )
    lines.append(
        f"- `OBJINDEX.bin` entries: {len(objindex)} "
        f"({sum(1 for value in objindex if value != -1)} explicit remaps)"
    )
    lines.append(
        f"- Object defs with non-identity `OBJINDEX` remaps in the live def range: "
        f"{remapped_record_count} / {len(records)}"
    )
    lines.append(
        f"- Placement-space IDs `0x0000`..`0x{len(records) - 1:04X}` collapse onto "
        f"{unique_targets_within_defs} canonical defs; max fanout in that range is 2"
    )
    lines.append(
        f"- Full `OBJINDEX.bin` max fanout is {max(remap_targets.values())}, with the lone outlier "
        f"`0x0000` fed by {remap_targets[0]} placement IDs"
    )
    lines.append(
        f"- Unique DLL IDs referenced at `+0x50`: "
        f"{len({record.dll_id for record in records})} "
        f"({sum(1 for record in records if record.dll_id != 0xFFFF)} defs have a non-`0xFFFF` DLL)"
    )
    lines.append(f"- Unique class IDs at `+0x52`: {len({record.class_id for record in records})}")
    lines.append(
        f"- Fixed map affinities at `+0x78`: "
        f"{sum(1 for record in records if record.map_id != 0xFFFF)} defs across "
        f"{len({record.map_id for record in records if record.map_id != 0xFFFF})} map IDs"
    )
    lines.append(
        f"- Defs with nonzero player-object counts: {sum(1 for record in records if record.n_player_objs != 0)}"
    )
    lines.append(f"- Defs with inline sequence lists: {sum(1 for record in records if record.sequence_ids)}")
    lines.append("")

    lines.append("## Record spans")
    for size, count in span_counter.most_common(12):
        lines.append(f"- `0x{size:X}` bytes: {count} defs")
    lines.append("")

    lines.append("## Inline substructure fields")
    for field_name, _field_offset in FIELD_SPECS:
        lines.append(f"- `{field_name}`: {field_inline_counts[field_name]} defs")
    lines.append("")

    lines.append("## High-usage DLL families")
    for dll_id, placements, defs, items in dll_groups[:12]:
        if dll_id == 0xFFFF:
            continue
        samples = ", ".join(f"`0x{item.def_id:04X}` `{item.name}`" for item in items[:4])
        lines.append(f"- `0x{dll_id:04X}`: placements={placements}, defs={defs}, samples={samples}")
    lines.append("")

    lines.append("## High-usage class families")
    for class_id, placements, defs, items in class_groups[:12]:
        samples = ", ".join(f"`0x{item.def_id:04X}` `{item.name}`" for item in items[:4])
        lines.append(f"- `0x{class_id:04X}`: placements={placements}, defs={defs}, samples={samples}")
    lines.append("")

    lines.append("## Fixed map affinities")
    for map_id, _placements, defs, items in fixed_map_groups[:12]:
        samples = ", ".join(f"`0x{item.def_id:04X}` `{item.name}`" for item in items[:5])
        lines.append(f"- `0x{map_id:02X}` `{items[0].map_name}`: defs={defs}, samples={samples}")
    lines.append("")

    lines.append("## Practical use")
    lines.append("- Summary: `python tools/orig/object_catalog.py`")
    lines.append("- CSV dump: `python tools/orig/object_catalog.py --format csv`")
    lines.append("- Search object/DLL/class/map IDs or names:")
    lines.append("  - `python tools/orig/object_catalog.py --search curve dll:0x0126 def:0x051C map:dimpushblock`")
    return "\n".join(lines)


def search_records(records: list[ObjectRecord], patterns: list[str]) -> list[ObjectRecord]:
    lowered = [pattern.lower() for pattern in patterns]
    matches: list[ObjectRecord] = []
    for record in records:
        matched = False
        for pattern in lowered:
            if pattern.startswith("def:"):
                value = pattern[4:]
                matched = value in (f"{record.def_id:04x}", f"0x{record.def_id:04x}")
            elif pattern.startswith("dll:"):
                value = pattern[4:]
                matched = value in (f"{record.dll_id:04x}", f"0x{record.dll_id:04x}")
            elif pattern.startswith("class:"):
                value = pattern[6:]
                matched = value in (f"{record.class_id & 0xFFFF:04x}", f"0x{record.class_id & 0xFFFF:04x}")
            elif pattern.startswith("map:"):
                value = pattern[4:]
                matched = (
                    record.map_name is not None
                    and (
                        value in record.map_name.lower()
                        or value in (f"{record.map_id:02x}", f"0x{record.map_id:02x}")
                    )
                )
            else:
                haystacks = [
                    record.name.lower(),
                    f"{record.def_id:04x}",
                    f"0x{record.def_id:04x}",
                    f"{record.dll_id:04x}",
                    f"0x{record.dll_id:04x}",
                    f"{record.class_id & 0xFFFF:04x}",
                    f"0x{record.class_id & 0xFFFF:04x}",
                ]
                if record.map_name is not None:
                    haystacks.extend([record.map_name.lower(), f"{record.map_id:02x}", f"0x{record.map_id:02x}"])
                matched = any(pattern in value for value in haystacks)
            if matched:
                break
        if matched:
            matches.append(record)
    return matches


def search_markdown(records: list[ObjectRecord], patterns: list[str]) -> str:
    matches = search_records(records, patterns)
    lines: list[str] = []
    lines.append("# Object search")
    lines.append("")
    if not matches:
        lines.append("- No matching object defs.")
        return "\n".join(lines)

    for record in matches[:40]:
        alias_text = (
            ", aliases=" + " ".join(f"0x{value:04X}" for value in record.remap_sources)
            if record.remap_sources
            else ""
        )
        map_text = (
            f", map=`0x{record.map_id:02X}` `{record.map_name}`"
            if record.map_name is not None
            else ""
        )
        lines.append(
            f"- `0x{record.def_id:04X}` `{record.name}`: "
            f"dll=`0x{record.dll_id:04X}`, class=`0x{record.class_id & 0xFFFF:04X}`, "
            f"placements={record.placements}, romlists={record.romlists}, "
            f"size=`0x{record.size:X}`{map_text}{alias_text}"
        )
        if record.model_ids:
            lines.append(f"  models: `{format_hex_list(record.model_ids)}`")
        if record.sequence_ids:
            lines.append(f"  seqs: `{format_hex_list(record.sequence_ids)}`")
        if record.inline_fields:
            lines.append(f"  inline fields: `{', '.join(record.inline_fields)}`")
    if len(matches) > 40:
        lines.append(f"- ... {len(matches) - 40} more matches omitted")
    return "\n".join(lines)


def rows_to_csv(records: list[ObjectRecord]) -> str:
    fieldnames = [
        "def_id",
        "def_id_hex",
        "offset_hex",
        "size_hex",
        "name",
        "remap_target_hex",
        "remap_sources",
        "placements",
        "romlists",
        "dll_id_hex",
        "class_id_hex",
        "n_models",
        "n_player_objs",
        "n_sequences",
        "map_id_hex",
        "map_name",
        "inline_fields",
        "model_ids",
        "sequence_ids",
        "help_texts",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for record in records:
        writer.writerow(
            {
                "def_id": record.def_id,
                "def_id_hex": f"0x{record.def_id:04X}",
                "offset_hex": f"0x{record.offset:06X}",
                "size_hex": f"0x{record.size:X}",
                "name": record.name,
                "remap_target_hex": f"0x{record.remap_target:04X}",
                "remap_sources": " ".join(f"0x{value:04X}" for value in record.remap_sources),
                "placements": record.placements,
                "romlists": record.romlists,
                "dll_id_hex": f"0x{record.dll_id:04X}",
                "class_id_hex": f"0x{record.class_id & 0xFFFF:04X}",
                "n_models": record.n_models,
                "n_player_objs": record.n_player_objs,
                "n_sequences": record.n_sequences,
                "map_id_hex": "" if record.map_id == 0xFFFF else f"0x{record.map_id:02X}",
                "map_name": record.map_name or "",
                "inline_fields": " ".join(record.inline_fields),
                "model_ids": " ".join(f"0x{value:04X}" for value in record.model_ids),
                "sequence_ids": " ".join(f"0x{value:04X}" for value in record.sequence_ids),
                "help_texts": " ".join(f"0x{value:04X}" for value in record.help_texts),
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover object, DLL, class, and inline-structure data from retail OBJECTS files.")
    parser.add_argument(
        "--files-root",
        type=Path,
        default=Path("orig/GSAE01/files"),
        help="Path to the extracted EN files/ directory.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "csv"),
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--search",
        nargs="+",
        help="Substring search across object names and hex IDs.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    objindex = load_objindex(args.files_root / "OBJINDEX.bin")
    placements, romlists_by_def = load_romlist_usage(args.files_root, objindex)
    records, raw_offsets = build_records(args.files_root, placements, romlists_by_def)

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(records))
        elif args.search:
            sys.stdout.write(search_markdown(records, args.search))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(records, raw_offsets, objindex))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
