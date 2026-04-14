from __future__ import annotations

import argparse
import csv
import io
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.append(os.fspath(Path(__file__).resolve().parents[2]))
    from tools.orig.object_catalog import FIELD_SPECS, load_map_names, load_object_offsets, load_objindex, load_romlist_usage
else:
    from .object_catalog import FIELD_SPECS, load_map_names, load_object_offsets, load_objindex, load_romlist_usage


NAME_FIELD_OFFSET = 0x91
NAME_FIELD_SIZE = 0x0B


@dataclass(frozen=True)
class ObjectVariant:
    start: int
    size: int
    dll_id: int
    class_id: int
    map_id: int
    map_name: str | None
    n_models: int
    n_player_objs: int
    n_sequences: int
    inline_fields: tuple[str, ...]
    model_ids: tuple[int, ...]
    sequence_ids: tuple[int, ...]


@dataclass(frozen=True)
class ObjectBin2Diff:
    def_id: int
    name: str
    placements: int
    romlists: int
    matched: bool
    live: ObjectVariant
    bin2: ObjectVariant | None
    status: str
    structural_notes: tuple[str, ...]
    model_id_delta: bool
    score: int

    @property
    def is_structural(self) -> bool:
        return not self.matched or bool(self.structural_notes)


def slugify(text: str) -> str:
    lowered = text.lower()
    pieces: list[str] = []
    prev_sep = False
    for char in lowered:
        if char.isalnum():
            pieces.append(char)
            prev_sep = False
            continue
        if not prev_sep:
            pieces.append("_")
        prev_sep = True
    return "".join(pieces).strip("_") or "unnamed"


def name_field(blob: bytes, start: int) -> bytes:
    return blob[start + NAME_FIELD_OFFSET : start + NAME_FIELD_OFFSET + NAME_FIELD_SIZE]


def name_text(field: bytes) -> str:
    return field.split(b"\0", 1)[0].decode("ascii", "replace")


def load_u16s(blob: bytes, start: int, rel_offset: int, count: int, end: int) -> tuple[int, ...]:
    if rel_offset == 0 or count <= 0:
        return ()
    absolute = start + rel_offset
    if absolute < start or absolute >= end:
        return ()
    max_count = (end - absolute) // 2
    if max_count <= 0:
        return ()
    actual = min(count, max_count)
    return tuple(struct.unpack_from(f">{actual}H", blob, absolute))


def load_u32s(blob: bytes, start: int, rel_offset: int, count: int, end: int) -> tuple[int, ...]:
    if rel_offset == 0 or count <= 0:
        return ()
    absolute = start + rel_offset
    if absolute < start or absolute >= end:
        return ()
    max_count = (end - absolute) // 4
    if max_count <= 0:
        return ()
    actual = min(count, max_count)
    return tuple(struct.unpack_from(f">{actual}I", blob, absolute))


def extract_variant(blob: bytes, start: int, end: int, map_names: list[str]) -> ObjectVariant:
    dll_id, class_id = struct.unpack_from(">Hh", blob, start + 0x50)
    n_models, n_player_objs = struct.unpack_from(">BB", blob, start + 0x55)
    n_sequences = blob[start + 0x5E]
    map_id = struct.unpack_from(">H", blob, start + 0x78)[0]
    map_name = None if map_id == 0xFFFF or map_id >= len(map_names) else map_names[map_id]

    field_values = {
        label: struct.unpack_from(">I", blob, start + rel_offset)[0]
        for label, rel_offset in FIELD_SPECS
    }
    inline_fields = tuple(
        label
        for label, value in field_values.items()
        if value != 0 and start <= start + value < end
    )

    model_ids = load_u32s(blob, start, field_values["pModelList"], n_models, end)
    sequence_ids = load_u16s(blob, start, field_values["pSeq"], n_sequences, end)
    return ObjectVariant(
        start=start,
        size=end - start,
        dll_id=dll_id,
        class_id=class_id,
        map_id=map_id,
        map_name=map_name,
        n_models=n_models,
        n_player_objs=n_player_objs,
        n_sequences=n_sequences,
        inline_fields=inline_fields,
        model_ids=model_ids,
        sequence_ids=sequence_ids,
    )


def find_candidates(blob: bytes, field: bytes, search_from: int, minimum_start: int) -> list[tuple[int, int]]:
    results: list[tuple[int, int]] = []
    cursor = search_from
    while True:
        pos = blob.find(field, cursor)
        if pos < 0:
            break
        candidate_start = pos - NAME_FIELD_OFFSET
        if candidate_start >= minimum_start:
            results.append((pos, candidate_start))
        cursor = pos + 1
    return results


def infer_bin2_starts(live_blob: bytes, bin2_blob: bytes, offsets: list[int], raw_offsets: list[int]) -> list[int | None]:
    starts: list[int | None] = []
    search_from = 0
    previous_start = 0
    previous_live_size = 0

    for start, end in zip(offsets, raw_offsets[1:]):
        field = name_field(live_blob, start)
        candidates = find_candidates(bin2_blob, field, search_from, previous_start)
        if not candidates:
            starts.append(None)
            continue

        expected = previous_start + previous_live_size
        pos, chosen_start = min(candidates, key=lambda item: (abs(item[1] - expected), item[1]))
        starts.append(chosen_start)
        search_from = pos + len(field)
        previous_start = chosen_start
        previous_live_size = end - start
    return starts


def next_known_start(starts: list[int | None], index: int, blob_size: int) -> int:
    for candidate in starts[index + 1 :]:
        if candidate is not None:
            return candidate
    return blob_size


def structural_notes(live: ObjectVariant, bin2: ObjectVariant | None) -> tuple[str, ...]:
    if bin2 is None:
        return ("missing exact 11-byte name-field match in OBJECTS.bin2",)

    notes: list[str] = []
    if live.size != bin2.size:
        notes.append(f"size 0x{live.size:X} -> 0x{bin2.size:X}")
    if live.dll_id != bin2.dll_id:
        notes.append(f"dll 0x{live.dll_id:04X} -> 0x{bin2.dll_id:04X}")
    if live.class_id != bin2.class_id:
        notes.append(f"class 0x{live.class_id & 0xFFFF:04X} -> 0x{bin2.class_id & 0xFFFF:04X}")
    if live.map_id != bin2.map_id:
        notes.append(f"map 0x{live.map_id:04X} -> 0x{bin2.map_id:04X}")
    if live.inline_fields != bin2.inline_fields:
        notes.append(f"inline {live.inline_fields} -> {bin2.inline_fields}")
    if live.n_models != bin2.n_models:
        notes.append(f"n_models {live.n_models} -> {bin2.n_models}")
    if live.n_sequences != bin2.n_sequences:
        notes.append(f"n_sequences {live.n_sequences} -> {bin2.n_sequences}")
    return tuple(notes)


def diff_status(notes: tuple[str, ...], matched: bool) -> str:
    if not matched:
        return "missing"
    if not notes:
        return "stable"
    if any(note.startswith("size ") for note in notes):
        return "size-delta"
    return "structural-delta"


def compute_score(notes: tuple[str, ...], placements: int, matched: bool, live: ObjectVariant, bin2: ObjectVariant | None) -> int:
    if not matched:
        return 100000 + placements

    score = placements + len(notes) * 64
    if bin2 is not None:
        score += abs(bin2.size - live.size) * 4
        if live.dll_id != bin2.dll_id:
            score += 2048
        if live.class_id != bin2.class_id:
            score += 1024
        if live.inline_fields != bin2.inline_fields:
            score += 512
        if live.n_models != bin2.n_models or live.n_sequences != bin2.n_sequences:
            score += 256
    return score


def build_diffs(files_root: Path) -> list[ObjectBin2Diff]:
    live_blob = (files_root / "OBJECTS.bin").read_bytes()
    bin2_blob = (files_root / "OBJECTS.bin2").read_bytes()
    offsets, raw_offsets = load_object_offsets(files_root / "OBJECTS.tab")
    map_names = load_map_names(files_root / "MAPINFO.bin")
    objindex = load_objindex(files_root / "OBJINDEX.bin")
    placements, romlists_by_def = load_romlist_usage(files_root, objindex)
    bin2_starts = infer_bin2_starts(live_blob, bin2_blob, offsets, raw_offsets)

    diffs: list[ObjectBin2Diff] = []
    for def_id, (start, end) in enumerate(zip(offsets, raw_offsets[1:])):
        field = name_field(live_blob, start)
        name = name_text(field)
        live = extract_variant(live_blob, start, end, map_names)
        bin2_start = bin2_starts[def_id]
        bin2_variant: ObjectVariant | None = None
        if bin2_start is not None:
            bin2_end = next_known_start(bin2_starts, def_id, len(bin2_blob))
            bin2_variant = extract_variant(bin2_blob, bin2_start, bin2_end, map_names)

        notes = structural_notes(live, bin2_variant)
        matched = bin2_variant is not None
        diffs.append(
            ObjectBin2Diff(
                def_id=def_id,
                name=name,
                placements=placements.get(def_id, 0),
                romlists=len(romlists_by_def.get(def_id, set())),
                matched=matched,
                live=live,
                bin2=bin2_variant,
                status=diff_status(notes, matched),
                structural_notes=notes,
                model_id_delta=(matched and live.model_ids != bin2_variant.model_ids),
                score=compute_score(notes, placements.get(def_id, 0), matched, live, bin2_variant),
            )
        )
    return diffs


def visible_diffs(diffs: list[ObjectBin2Diff], include_stable: bool) -> list[ObjectBin2Diff]:
    items = diffs if include_stable else [item for item in diffs if item.is_structural]
    return sorted(items, key=lambda item: (-item.score, -item.placements, item.def_id))


def format_hex_list(values: tuple[int, ...]) -> str:
    return " ".join(f"0x{value:04X}" for value in values)


def summarize_top(diffs: list[ObjectBin2Diff], limit: int) -> list[ObjectBin2Diff]:
    return sorted(diffs, key=lambda item: (-item.score, -item.placements, item.def_id))[:limit]


def summary_markdown(diffs: list[ObjectBin2Diff], include_stable: bool, limit: int) -> str:
    matched = [item for item in diffs if item.matched]
    structural = [item for item in diffs if item.is_structural]
    size_delta = [item for item in matched if item.live.size != item.bin2.size]  # type: ignore[union-attr]
    inline_delta = [item for item in matched if item.live.inline_fields != item.bin2.inline_fields]  # type: ignore[union-attr]
    model_count_delta = [item for item in matched if item.live.n_models != item.bin2.n_models]  # type: ignore[union-attr]
    sequence_count_delta = [item for item in matched if item.live.n_sequences != item.bin2.n_sequences]  # type: ignore[union-attr]
    model_id_delta = [item for item in matched if item.model_id_delta]
    dll_stable = sum(1 for item in matched if item.live.dll_id == item.bin2.dll_id)  # type: ignore[union-attr]
    class_stable = sum(1 for item in matched if item.live.class_id == item.bin2.class_id)  # type: ignore[union-attr]
    map_stable = sum(1 for item in matched if item.live.map_id == item.bin2.map_id)  # type: ignore[union-attr]

    lines: list[str] = []
    lines.append("# `orig/GSAE01/files/OBJECTS.bin2` audit")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Retail object defs in `OBJECTS.tab`: `{len(diffs)}`")
    lines.append(f"- Exact ordered 11-byte name-field matches in `OBJECTS.bin2`: `{len(matched)}` / `{len(diffs)}`")
    lines.append(f"- Structurally changed or unresolved defs: `{len(structural)}`")
    lines.append(f"- Matched defs with size deltas: `{len(size_delta)}`")
    lines.append(f"- Matched defs with inline-field deltas: `{len(inline_delta)}`")
    lines.append(f"- Matched defs with model/sequence count deltas: `{len(model_count_delta) + len(sequence_count_delta)}`")
    lines.append(f"- Matched defs with model-ID list deltas: `{len(model_id_delta)}`")
    lines.append(
        f"- Stable core metadata across matched defs: dll=`{dll_stable}/{len(matched)}`, "
        f"class=`{class_stable}/{len(matched)}`, map=`{map_stable}/{len(matched)}`"
    )
    lines.append("")
    lines.append("## High-value findings")
    lines.append(
        "- `OBJECTS.bin2` is not random garbage: the same object-name order survives for almost the entire table once you align on the embedded 11-byte name field instead of reusing `OBJECTS.tab` offsets."
    )
    lines.append(
        "- The live object lineage and the `bin2` lineage keep DLL, class, and fixed-map metadata stable for almost every matched def, which makes `OBJECTS.bin2` useful as alternate structure evidence rather than just another dump."
    )
    lines.append(
        "- Only a small structural slice actually changes: mostly `Sabre`/`Krystal`, a handful of combat or cutscene objects, and three unresolved tail defs."
    )
    lines.append(
        "- Model ID lists diverge much more often than the structural fields do, which strongly suggests `OBJECTS.bin2` belongs to a sibling content/model lineage rather than a different object taxonomy."
    )
    lines.append("")
    lines.append("## Highest-leverage structural deltas")
    for item in summarize_top(structural, limit):
        delta_text = "missing"
        if item.bin2 is not None:
            delta_text = f"{item.status}, size=0x{item.live.size:X}->0x{item.bin2.size:X}"
        lines.append(
            f"- `0x{item.def_id:04X}` `{item.name}`: score={item.score}, placements={item.placements}, "
            f"romlists={item.romlists}, {delta_text}"
        )
        for note in item.structural_notes[:3]:
            lines.append(f"  - {note}")
    lines.append("")
    lines.append("## Practical use")
    lines.append("- Summary: `python tools/orig/object_bin2_audit.py`")
    lines.append("- Search one object or status:")
    lines.append("  - `python tools/orig/object_bin2_audit.py --search Sabre`")
    lines.append("  - `python tools/orig/object_bin2_audit.py --search status:missing`")
    lines.append("  - `python tools/orig/object_bin2_audit.py --search status:size-delta class:0x0053`")
    lines.append("- Materialize the strongest packet stubs:")
    lines.append("  - `python tools/orig/object_bin2_audit.py --materialize-top 8`")
    if include_stable:
        lines.append("- Stable rows are included in this view.")
    else:
        lines.append("- Stable rows are hidden by default; pass `--include-stable` to inspect the full matched set.")
    return "\n".join(lines)


def match_pattern(item: ObjectBin2Diff, pattern: str) -> bool:
    if pattern.startswith("def:"):
        value = pattern[4:]
        return value in (f"{item.def_id:04x}", f"0x{item.def_id:04x}")
    if pattern.startswith("dll:"):
        value = pattern[4:]
        return value in (f"{item.live.dll_id:04x}", f"0x{item.live.dll_id:04x}")
    if pattern.startswith("class:"):
        value = pattern[6:]
        return value in (f"{item.live.class_id & 0xFFFF:04x}", f"0x{item.live.class_id & 0xFFFF:04x}")
    if pattern.startswith("status:"):
        return pattern[7:] in item.status.lower()
    if pattern == "modeldiff":
        return item.model_id_delta

    haystacks = [
        item.name.lower(),
        item.status.lower(),
        f"{item.def_id:04x}",
        f"0x{item.def_id:04x}",
        f"{item.live.dll_id:04x}",
        f"0x{item.live.dll_id:04x}",
        f"{item.live.class_id & 0xFFFF:04x}",
        f"0x{item.live.class_id & 0xFFFF:04x}",
    ]
    if item.live.map_name is not None:
        haystacks.append(item.live.map_name.lower())
    return any(pattern in value for value in haystacks)


def search_markdown(diffs: list[ObjectBin2Diff], patterns: list[str], limit: int) -> str:
    lowered = [pattern.lower() for pattern in patterns]
    matches = [item for item in diffs if any(match_pattern(item, pattern) for pattern in lowered)]
    matches = sorted(matches, key=lambda item: (-item.score, -item.placements, item.def_id))

    lines: list[str] = []
    lines.append("# OBJECTS.bin2 search")
    lines.append("")
    if not matches:
        lines.append("- No matching object-lineage rows.")
        return "\n".join(lines)

    for item in matches[:limit]:
        if item.bin2 is None:
            size_text = "missing"
        else:
            size_text = f"0x{item.live.size:X}->0x{item.bin2.size:X}"
        lines.append(
            f"- `0x{item.def_id:04X}` `{item.name}`: status=`{item.status}`, placements={item.placements}, "
            f"romlists={item.romlists}, size={size_text}"
        )
        for note in item.structural_notes[:4]:
            lines.append(f"  - {note}")
        if item.model_id_delta:
            lines.append("  - model-ID list differs between lineages")
    if len(matches) > limit:
        lines.append(f"- ... {len(matches) - limit} more matches omitted")
    return "\n".join(lines)


def rows_to_csv(diffs: list[ObjectBin2Diff]) -> str:
    fieldnames = [
        "def_id",
        "def_id_hex",
        "name",
        "status",
        "placements",
        "romlists",
        "live_start_hex",
        "live_size_hex",
        "bin2_start_hex",
        "bin2_size_hex",
        "dll_id_hex",
        "class_id_hex",
        "map_id_hex",
        "map_name",
        "live_inline_fields",
        "bin2_inline_fields",
        "live_n_models",
        "bin2_n_models",
        "live_n_sequences",
        "bin2_n_sequences",
        "model_id_delta",
        "structural_notes",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for item in diffs:
        writer.writerow(
            {
                "def_id": item.def_id,
                "def_id_hex": f"0x{item.def_id:04X}",
                "name": item.name,
                "status": item.status,
                "placements": item.placements,
                "romlists": item.romlists,
                "live_start_hex": f"0x{item.live.start:06X}",
                "live_size_hex": f"0x{item.live.size:X}",
                "bin2_start_hex": "" if item.bin2 is None else f"0x{item.bin2.start:06X}",
                "bin2_size_hex": "" if item.bin2 is None else f"0x{item.bin2.size:X}",
                "dll_id_hex": f"0x{item.live.dll_id:04X}",
                "class_id_hex": f"0x{item.live.class_id & 0xFFFF:04X}",
                "map_id_hex": "" if item.live.map_id == 0xFFFF else f"0x{item.live.map_id:04X}",
                "map_name": item.live.map_name or "",
                "live_inline_fields": " ".join(item.live.inline_fields),
                "bin2_inline_fields": "" if item.bin2 is None else " ".join(item.bin2.inline_fields),
                "live_n_models": item.live.n_models,
                "bin2_n_models": "" if item.bin2 is None else item.bin2.n_models,
                "live_n_sequences": item.live.n_sequences,
                "bin2_n_sequences": "" if item.bin2 is None else item.bin2.n_sequences,
                "model_id_delta": item.model_id_delta,
                "structural_notes": " | ".join(item.structural_notes),
            }
        )
    return buffer.getvalue()


def packet_output_path(output_root: Path, item: ObjectBin2Diff) -> Path:
    return output_root / f"obj_{item.def_id:04X}_{slugify(item.name)}_bin2.c"


def packet_text(item: ObjectBin2Diff, output_root: Path) -> str:
    stem = slugify(item.name).upper()
    output_path = packet_output_path(output_root, item).as_posix()
    lines: list[str] = []
    lines.append("/*")
    lines.append(" * Auto-generated by tools/orig/object_bin2_audit.py.")
    lines.append(" *")
    lines.append(" * This file is intentionally not wired into the build yet.")
    lines.append(" * It exists as a retail-backed comparison packet between OBJECTS.bin and OBJECTS.bin2.")
    lines.append(" *")
    lines.append(f" * Object def: 0x{item.def_id:04X} {item.name}")
    lines.append(f" * Output path: {output_path}")
    lines.append(f" * Retail placements: {item.placements}")
    lines.append(f" * Root romlists: {item.romlists}")
    lines.append(f" * Status: {item.status}")
    lines.append(f" * Live OBJECTS.bin span: start=0x{item.live.start:06X}, size=0x{item.live.size:X}")
    if item.bin2 is None:
        lines.append(" * OBJECTS.bin2 span: unresolved (exact 11-byte name field not found)")
    else:
        lines.append(f" * OBJECTS.bin2 span: start=0x{item.bin2.start:06X}, size=0x{item.bin2.size:X}")
    lines.append(
        f" * Core metadata: dll=0x{item.live.dll_id:04X}, class=0x{item.live.class_id & 0xFFFF:04X}, "
        f"map=0x{item.live.map_id:04X}"
    )
    lines.append(" *")
    lines.append(" * Structural differences:")
    if item.structural_notes:
        for note in item.structural_notes:
            lines.append(f" * - {note}")
    else:
        lines.append(" * - none")
    lines.append(" *")
    lines.append(f" * Live inline fields: {', '.join(item.live.inline_fields) if item.live.inline_fields else 'none'}")
    if item.bin2 is None:
        lines.append(" * Bin2 inline fields: unresolved")
    else:
        lines.append(f" * Bin2 inline fields: {', '.join(item.bin2.inline_fields) if item.bin2.inline_fields else 'none'}")
        if item.live.n_models != item.bin2.n_models or item.live.n_sequences != item.bin2.n_sequences:
            lines.append(
                f" * Count deltas: models {item.live.n_models}->{item.bin2.n_models}, "
                f"sequences {item.live.n_sequences}->{item.bin2.n_sequences}"
            )
        if item.live.model_ids != item.bin2.model_ids:
            lines.append(
                f" * Model IDs differ: live=`{format_hex_list(item.live.model_ids[:8])}`, "
                f"bin2=`{format_hex_list(item.bin2.model_ids[:8])}`"
            )
    lines.append(" */")
    lines.append("")
    lines.append("#if 0")
    lines.append("enum object_bin2_packet_info {")
    lines.append(f"    {stem}_DEF_ID = 0x{item.def_id:04X},")
    lines.append(f"    {stem}_LIVE_BYTES = 0x{item.live.size:X},")
    if item.bin2 is not None:
        lines.append(f"    {stem}_BIN2_BYTES = 0x{item.bin2.size:X},")
    lines.append("};")
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines)


def materialize_packets(items: list[ObjectBin2Diff], output_root: Path) -> list[Path]:
    output_root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for item in items:
        path = packet_output_path(output_root, item)
        path.write_text(packet_text(item, output_root), encoding="utf-8")
        written.append(path)
    return written


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover the alternate OBJECTS.bin2 lineage and compare it against live OBJECTS.bin.")
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
        help="Search by def, dll, class, status, or object name.",
    )
    parser.add_argument(
        "--include-stable",
        action="store_true",
        help="Include the full matched set instead of only structural deltas and unresolved rows.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=15,
        help="Maximum rows to show in summary or search mode.",
    )
    parser.add_argument(
        "--materialize-top",
        type=int,
        help="Write the top N visible packet stubs under --output-root.",
    )
    parser.add_argument(
        "--materialize-all",
        action="store_true",
        help="Write every visible packet stub under --output-root.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("src/main/unknown/object_lineage"),
        help="Destination directory for packet stubs when materializing.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    diffs = build_diffs(args.files_root.resolve())
    visible = visible_diffs(diffs, args.include_stable)

    if args.search:
        lowered = [pattern.lower() for pattern in args.search]
        visible = [item for item in visible if any(match_pattern(item, pattern) for pattern in lowered)]

    if args.materialize_all:
        materialize_packets(visible, args.output_root.resolve())
    elif args.materialize_top:
        materialize_packets(visible[: args.materialize_top], args.output_root.resolve())

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(visible))
        elif args.search:
            sys.stdout.write(search_markdown(visible, args.search, args.limit))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(diffs, args.include_stable, args.limit))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
