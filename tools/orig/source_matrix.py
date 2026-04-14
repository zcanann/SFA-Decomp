from __future__ import annotations

import argparse
import csv
import io
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.orig.dol_xrefs import DolFile, scan_strings
from tools.orig.source_leaks import collect_direct_source_artifacts
from tools.orig.source_recovery import (
    RecoveryGroup,
    clean_context_text,
    collect_candidates,
    extract_retail_context,
    extract_source_name,
    format_function_name,
    group_candidates,
    normalize_token,
    top_named_functions,
)


@dataclass(frozen=True)
class BundleSpec:
    bundle_id: str
    label: str
    root: Path

    @property
    def dol_path(self) -> Path:
        return self.root / "sys/main.dol"


@dataclass(frozen=True)
class BundleSourceHit:
    bundle_id: str
    bundle_label: str
    source_name: str
    address: int
    text: str
    label: str | None
    message: str | None


@dataclass(frozen=True)
class BundleSourceEvidence:
    source_name: str
    exact_hits: tuple[BundleSourceHit, ...]
    alias_names: tuple[str, ...]
    alias_hits: tuple[BundleSourceHit, ...]

    @property
    def exact_bundle_ids(self) -> tuple[str, ...]:
        seen: set[str] = set()
        values: list[str] = []
        for hit in self.exact_hits:
            if hit.bundle_id in seen:
                continue
            seen.add(hit.bundle_id)
            values.append(hit.bundle_id)
        return tuple(values)

    @property
    def all_hits(self) -> tuple[BundleSourceHit, ...]:
        return self.exact_hits + self.alias_hits

    @property
    def all_bundle_ids(self) -> tuple[str, ...]:
        seen: set[str] = set()
        values: list[str] = []
        for hit in self.all_hits:
            if hit.bundle_id in seen:
                continue
            seen.add(hit.bundle_id)
            values.append(hit.bundle_id)
        return tuple(values)


DEFAULT_BUNDLES = (
    ("GSAE01", "EN v1.0", Path("orig/GSAE01")),
    ("GSAE01_rev1", "EN rev1", Path("orig/GSAE01_rev1")),
    ("GSAP01", "PAL", Path("orig/GSAP01")),
    ("GSAJ01", "JP", Path("orig/GSAJ01")),
)


def default_bundle_specs() -> tuple[BundleSpec, ...]:
    specs: list[BundleSpec] = []
    for bundle_id, label, root in DEFAULT_BUNDLES:
        if (root / "sys/main.dol").is_file():
            specs.append(BundleSpec(bundle_id=bundle_id, label=label, root=root))
    return tuple(specs)


def collect_bundle_source_hits(spec: BundleSpec) -> list[BundleSourceHit]:
    dol = DolFile(spec.dol_path)
    hits: list[BundleSourceHit] = []
    for entry in scan_strings(dol):
        if "source" not in entry.tags:
            continue
        source_name = extract_source_name(entry.text)
        if source_name is None:
            continue
        retail_label, retail_message = extract_retail_context(entry.text, source_name)
        hits.append(
            BundleSourceHit(
                bundle_id=spec.bundle_id,
                bundle_label=spec.label,
                source_name=source_name,
                address=entry.address,
                text=entry.text,
                label=retail_label,
                message=retail_message,
            )
        )
    hits.sort(key=lambda item: (item.source_name.lower(), item.bundle_id, item.address))
    return hits


def collect_all_bundle_source_hits(specs: tuple[BundleSpec, ...]) -> list[BundleSourceHit]:
    hits: list[BundleSourceHit] = []
    for spec in specs:
        hits.extend(collect_bundle_source_hits(spec))
    hits.sort(key=lambda item: (item.source_name.lower(), item.bundle_id, item.address))
    return hits


def source_context_signature(hits: tuple[BundleSourceHit, ...]) -> tuple[tuple[str, str], ...]:
    values = {
        (
            normalize_token(hit.label or ""),
            normalize_token(hit.message or ""),
        )
        for hit in hits
    }
    return tuple(sorted(values))


def stems_related(left: str, right: str) -> bool:
    left_stem = normalize_token(Path(left).stem)
    right_stem = normalize_token(Path(right).stem)
    if not left_stem or not right_stem or left_stem == right_stem:
        return False
    if len(left_stem) < 5 or len(right_stem) < 5:
        return False
    return left_stem in right_stem or right_stem in left_stem


def build_source_variant_index(hits: list[BundleSourceHit]) -> dict[str, BundleSourceEvidence]:
    exact_groups: dict[str, list[BundleSourceHit]] = {}
    for hit in hits:
        exact_groups.setdefault(hit.source_name.lower(), []).append(hit)

    exact_names = list(exact_groups.keys())
    alias_map: dict[str, set[str]] = {name: set() for name in exact_names}
    signatures = {
        name: source_context_signature(tuple(values))
        for name, values in exact_groups.items()
    }

    for index, left_name in enumerate(exact_names):
        for right_name in exact_names[index + 1 :]:
            if signatures[left_name] != signatures[right_name]:
                continue
            left_values = exact_groups[left_name]
            right_values = exact_groups[right_name]
            if not left_values or not right_values:
                continue
            if not stems_related(left_values[0].source_name, right_values[0].source_name):
                continue
            alias_map[left_name].add(right_name)
            alias_map[right_name].add(left_name)

    result: dict[str, BundleSourceEvidence] = {}
    for name, values in exact_groups.items():
        alias_hits: list[BundleSourceHit] = []
        alias_names: list[str] = []
        for alias_name in sorted(alias_map[name]):
            alias_values = exact_groups[alias_name]
            alias_hits.extend(alias_values)
            alias_names.append(alias_values[0].source_name)
        result[name] = BundleSourceEvidence(
            source_name=values[0].source_name,
            exact_hits=tuple(values),
            alias_names=tuple(alias_names),
            alias_hits=tuple(alias_hits),
        )
    return result


def build_en_groups(
    debug_symbols: Path,
    debug_splits: Path,
    debug_srcfiles: Path,
) -> list[RecoveryGroup]:
    candidates = collect_candidates(
        retail_strings_path=Path("orig/GSAE01/sys/main.dol"),
        retail_symbols_path=Path("config/GSAE01/symbols.txt"),
        debug_symbols_path=debug_symbols,
        debug_splits_path=debug_splits,
        debug_srcfiles_path=debug_srcfiles,
    )
    return group_candidates(candidates)


def en_group_index(groups: list[RecoveryGroup]) -> dict[str, RecoveryGroup]:
    return {group.retail_source_name.lower(): group for group in groups}


def nearby_source_strings(spec: BundleSpec, address: int, radius: int = 2) -> list[str]:
    dol = DolFile(spec.dol_path)
    strings = [
        entry
        for entry in scan_strings(dol)
        if clean_context_text(entry.text) is not None
    ]
    index_by_address = {entry.address: index for index, entry in enumerate(strings)}
    index = index_by_address.get(address)
    if index is None:
        return []
    values: list[str] = []
    for offset in range(max(0, index - radius), min(len(strings), index + radius + 1)):
        if offset == index:
            continue
        cleaned = clean_context_text(strings[offset].text)
        if cleaned is None:
            continue
        values.append(cleaned)
    return values


def direct_artifact_rows(specs: tuple[BundleSpec, ...]) -> list[tuple[str, str, list[str]]]:
    grouped: dict[str, tuple[str, list[str]]] = {}
    for spec in specs:
        for artifact in collect_direct_source_artifacts(spec.root):
            tokens = ", ".join(artifact.source_tokens[:3])
            entry = grouped.setdefault(artifact.relative_path, (tokens, []))
            entry[1].append(spec.bundle_id)
    rows: list[tuple[str, str, list[str]]] = []
    for relative_path, (tokens, bundle_ids) in grouped.items():
        rows.append((relative_path, tokens, bundle_ids))
    rows.sort(key=lambda item: (-len(item[2]), item[0].lower()))
    return rows


def stable_groups(
    evidence_index: dict[str, BundleSourceEvidence],
    en_index: dict[str, RecoveryGroup],
) -> list[BundleSourceEvidence]:
    values = [
        evidence
        for evidence in evidence_index.values()
        if len(evidence.exact_bundle_ids) >= 3
    ]
    values.sort(
        key=lambda item: (
            -(1 if item.source_name.lower() in en_index and en_index[item.source_name.lower()].xrefs else 0),
            -len(item.all_bundle_ids),
            item.source_name.lower(),
        )
    )
    return values


def weak_groups(
    evidence_index: dict[str, BundleSourceEvidence],
    en_index: dict[str, RecoveryGroup],
) -> list[BundleSourceEvidence]:
    values: list[BundleSourceEvidence] = []
    for evidence in evidence_index.values():
        if len(evidence.all_bundle_ids) < 3:
            continue
        if len(evidence.exact_bundle_ids) < 3:
            continue
        group = en_index.get(evidence.source_name.lower())
        if group is None:
            continue
        if group.xrefs:
            continue
        values.append(evidence)
    values.sort(key=lambda item: (-len(item.all_bundle_ids), item.source_name.lower()))
    return values


def alias_groups(
    evidence_index: dict[str, BundleSourceEvidence],
) -> list[BundleSourceEvidence]:
    values = [evidence for evidence in evidence_index.values() if evidence.alias_names]
    values.sort(key=lambda item: item.source_name.lower())
    return values


def alias_pairs(
    evidence_index: dict[str, BundleSourceEvidence],
) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    for evidence in alias_groups(evidence_index):
        for alias_name in evidence.alias_names:
            seen.add(tuple(sorted((evidence.source_name, alias_name), key=str.lower)))
    return sorted(seen, key=lambda item: (item[0].lower(), item[1].lower()))


def bundle_hits_preview(hits: tuple[BundleSourceHit, ...], limit: int = 6) -> str:
    parts: list[str] = []
    for hit in hits[:limit]:
        context = hit.message or hit.label or clean_context_text(hit.text) or hit.text
        parts.append(f"`{hit.bundle_id}` `0x{hit.address:08X}` `{context}`")
    return ", ".join(parts)


def group_summary_line(group: RecoveryGroup | None) -> str:
    if group is None:
        return "none"
    if group.xrefs:
        return ", ".join(f"`{format_function_name(xref)}`" for xref in group.xrefs[:4])
    if group.debug_sources:
        return ", ".join(f"`{source.path}`" for source in group.debug_sources[:2])
    return "none"


def summary_markdown(
    specs: tuple[BundleSpec, ...],
    evidence_index: dict[str, BundleSourceEvidence],
    en_groups: list[RecoveryGroup],
) -> str:
    en_index = en_group_index(en_groups)
    stable = stable_groups(evidence_index, en_index)
    weak = weak_groups(evidence_index, en_index)
    aliases = alias_pairs(evidence_index)
    artifacts = direct_artifact_rows(specs)

    lines: list[str] = []
    lines.append("# Cross-bundle source audit")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Bundles scanned: `{len(specs)}`")
    lines.append(f"- Unique source-tagged basenames across all bundles: `{len(evidence_index)}`")
    lines.append(f"- Source names present in 3+ bundles: `{len(stable)}`")
    lines.append(f"- Cross-version weak EN candidates with no direct EN xref: `{len(weak)}`")
    lines.append(f"- Alias / rename candidates across bundles: `{len(aliases)}`")
    lines.append(f"- Direct `.c.new` / `.h.bak` artifact paths across bundles: `{len(artifacts)}`")
    lines.append("")

    lines.append("## Cross-version stable source tags")
    for evidence in stable[:12]:
        group = en_index.get(evidence.source_name.lower())
        bundle_ids = ", ".join(f"`{bundle_id}`" for bundle_id in evidence.all_bundle_ids)
        lines.append(f"- `{evidence.source_name}` bundles={bundle_ids}")
        lines.append(f"  bundle hits: {bundle_hits_preview(evidence.all_hits)}")
        if evidence.alias_names:
            lines.append("  alias names: " + ", ".join(f"`{name}`" for name in evidence.alias_names))
        lines.append(f"  EN crosswalk: {group_summary_line(group)}")
        if group is not None and group.debug_sources:
            debug_preview = ", ".join(f"`{source.path}`" for source in group.debug_sources[:2])
            lines.append(f"  debug paths: {debug_preview}")
    lines.append("")

    lines.append("## Cross-version weak leads")
    if weak:
        spec_by_id = {spec.bundle_id: spec for spec in specs}
        for evidence in weak:
            group = en_index.get(evidence.source_name.lower())
            lines.append(
                f"- `{evidence.source_name}` bundles="
                + ", ".join(f"`{bundle_id}`" for bundle_id in evidence.all_bundle_ids)
            )
            lines.append(f"  bundle hits: {bundle_hits_preview(evidence.all_hits)}")
            if group is not None and group.debug_sources:
                lines.append(
                    "  debug paths: "
                    + ", ".join(f"`{source.path}`" for source in group.debug_sources[:2])
                )
            en_hit = next((hit for hit in evidence.all_hits if hit.bundle_id == "GSAE01"), None)
            if en_hit is not None:
                nearby = nearby_source_strings(spec_by_id["GSAE01"], en_hit.address)
                if nearby:
                    lines.append(
                        "  nearby EN strings: "
                        + ", ".join(f"`{value}`" for value in nearby[:4])
                    )
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Alias / rename candidates")
    if aliases:
        for left_name, right_name in aliases:
            evidence = evidence_index[left_name.lower()]
            group = en_index.get(left_name.lower())
            lines.append(f"- `{left_name}` <-> `{right_name}`")
            lines.append(f"  bundle hits: {bundle_hits_preview(evidence.all_hits)}")
            lines.append(f"  EN crosswalk: {group_summary_line(group)}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Direct source/header artifact availability")
    for relative_path, tokens, bundle_ids in artifacts[:16]:
        bundle_preview = ", ".join(f"`{bundle_id}`" for bundle_id in bundle_ids)
        lines.append(f"- `{relative_path}` bundles={bundle_preview}")
        if tokens:
            lines.append(f"  embedded tokens: `{tokens}`")
    lines.append("")

    lines.append("## Usage")
    lines.append("- Summary: `python tools/orig/source_matrix.py`")
    lines.append("- Search one source or bundle: `python tools/orig/source_matrix.py --search n_attractmode hcurves GSAJ01`")
    lines.append("- CSV dump: `python tools/orig/source_matrix.py --format csv`")
    return "\n".join(lines)


def search_markdown(
    specs: tuple[BundleSpec, ...],
    evidence_index: dict[str, BundleSourceEvidence],
    en_groups: list[RecoveryGroup],
    patterns: list[str],
) -> str:
    lowered = [pattern.lower() for pattern in patterns]
    en_index = en_group_index(en_groups)
    artifacts = direct_artifact_rows(specs)

    lines = ["# Cross-bundle source search", ""]

    matched_any = False
    for evidence in sorted(evidence_index.values(), key=lambda item: item.source_name.lower()):
        group = en_index.get(evidence.source_name.lower())
        fields = [evidence.source_name.lower()]
        fields.extend(name.lower() for name in evidence.alias_names)
        fields.extend(hit.bundle_id.lower() for hit in evidence.all_hits)
        fields.extend(hit.text.lower() for hit in evidence.all_hits)
        if group is not None:
            fields.extend(format_function_name(xref).lower() for xref in group.xrefs)
            fields.extend(source.path.lower() for source in group.debug_sources)
        if not any(any(pattern in field for field in fields) for pattern in lowered):
            continue
        matched_any = True
        lines.append(f"- `{evidence.source_name}`")
        lines.append(
            "  bundles: "
            + ", ".join(f"`{bundle_id}`" for bundle_id in evidence.all_bundle_ids)
        )
        lines.append(f"  hits: {bundle_hits_preview(evidence.all_hits)}")
        if evidence.alias_names:
            lines.append("  alias names: " + ", ".join(f"`{name}`" for name in evidence.alias_names))
        if group is not None and group.xrefs:
            lines.append(
                "  EN xrefs: " + ", ".join(f"`{format_function_name(xref)}`" for xref in group.xrefs[:6])
            )
        elif group is not None and group.debug_sources:
            lines.append(
                "  debug paths: " + ", ".join(f"`{source.path}`" for source in group.debug_sources[:3])
            )
        else:
            lines.append("  EN crosswalk: none")

    for relative_path, tokens, bundle_ids in artifacts:
        fields = [relative_path.lower(), tokens.lower()]
        fields.extend(bundle_id.lower() for bundle_id in bundle_ids)
        if not any(any(pattern in field for field in fields) for pattern in lowered):
            continue
        matched_any = True
        lines.append(f"- artifact `{relative_path}`")
        lines.append("  bundles: " + ", ".join(f"`{bundle_id}`" for bundle_id in bundle_ids))
        if tokens:
            lines.append(f"  embedded tokens: `{tokens}`")

    if not matched_any:
        lines.append("- No matching cross-bundle source evidence.")
    return "\n".join(lines)


def rows_to_csv(
    evidence_index: dict[str, BundleSourceEvidence],
    en_groups: list[RecoveryGroup],
) -> str:
    en_index = en_group_index(en_groups)
    fieldnames = [
        "source_name",
        "alias_names",
        "bundle_ids",
        "bundle_addresses",
        "bundle_texts",
        "en_xrefs",
        "debug_paths",
        "debug_named_functions",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for evidence in sorted(evidence_index.values(), key=lambda item: item.source_name.lower()):
        group = en_index.get(evidence.source_name.lower())
        writer.writerow(
            {
                "source_name": evidence.source_name,
                "alias_names": ",".join(evidence.alias_names),
                "bundle_ids": ",".join(evidence.all_bundle_ids),
                "bundle_addresses": ",".join(f"{hit.bundle_id}:0x{hit.address:08X}" for hit in evidence.all_hits),
                "bundle_texts": " | ".join(hit.text for hit in evidence.all_hits),
                "en_xrefs": "" if group is None else ",".join(format_function_name(xref) for xref in group.xrefs),
                "debug_paths": "" if group is None else ",".join(source.path for source in group.debug_sources),
                "debug_named_functions": ""
                if group is None
                else ",".join(top_named_functions(group.debug_sources, group.debug_symbol_hits, 12)),
            }
        )
    return buffer.getvalue()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare retail source-tag strings and direct source artifacts across EN/PAL/JP bundles."
    )
    parser.add_argument(
        "--debug-symbols",
        type=Path,
        default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/symbols.txt"),
        help="Debug-side symbols used only as side evidence for the EN crosswalk.",
    )
    parser.add_argument(
        "--debug-splits",
        type=Path,
        default=Path("reference_projects/rena-tools/sfadebug/config/GSAP01-DEBUG/splits.txt"),
        help="Debug-side splits used only as side evidence for the EN crosswalk.",
    )
    parser.add_argument(
        "--debug-srcfiles",
        type=Path,
        default=Path("reference_projects/rena-tools/sfadebug/notes/srcfiles.txt"),
        help="Debug-side source filename inventory used only as side evidence for the EN crosswalk.",
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
        help="Case-insensitive substring search across source names, bundle ids, texts, and artifact paths.",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    specs = default_bundle_specs()
    hits = collect_all_bundle_source_hits(specs)
    evidence_index = build_source_variant_index(hits)
    en_groups = build_en_groups(
        debug_symbols=args.debug_symbols,
        debug_splits=args.debug_splits,
        debug_srcfiles=args.debug_srcfiles,
    )

    try:
        if args.format == "csv":
            sys.stdout.write(rows_to_csv(evidence_index, en_groups))
        elif args.search:
            sys.stdout.write(search_markdown(specs, evidence_index, en_groups, args.search))
            sys.stdout.write("\n")
        else:
            sys.stdout.write(summary_markdown(specs, evidence_index, en_groups))
            sys.stdout.write("\n")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
