from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


SYMBOL_RE = re.compile(
    r"^(?P<name>[A-Za-z_][\w$@]*)\s*=\s*\.text:0x(?P<addr>[0-9A-Fa-f]+);"
)
FUN_REF_RE = re.compile(r"\bFUN_(?P<addr>[0-9A-Fa-f]{8})\b")
FUNCTION_DEF_RE = re.compile(
    r"(?m)^\s*(?:[A-Za-z_][\w\s\*]*\s+)?(?P<name>[A-Za-z_][\w]*)\s*"
    r"\([^;{}]*\)\s*\{"
)


DEFAULT_IGNORED_NAMES = {
    "memcpy",
    "memset",
    # This address currently behaves like an inlined math/vector helper in
    # callers; the exported SDK-style name is not enough evidence by itself.
    "SeekTwiceBeforeRead",
}


@dataclass(frozen=True)
class Candidate:
    address: str
    target_name: str
    path: Path
    line: int
    role: str
    has_target_in_file: bool
    target_definition_count: int
    same_address_definition_count: int

    @property
    def risk(self) -> str:
        if self.has_target_in_file:
            return "same-file"
        if self.target_definition_count:
            return "defined-elsewhere"
        if self.role == "definition" and self.same_address_definition_count > 1:
            return "multi-body"
        if self.role == "definition":
            return "rename-body"
        return "rename-ref"


def load_text(path: Path) -> str:
    return path.read_text(errors="ignore")


def load_named_symbols(path: Path) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for line in load_text(path).splitlines():
        match = SYMBOL_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        if name.startswith(("FUN_", "fn_", "lbl_")) or "@" in name:
            continue
        address = match.group("addr").lower().zfill(8)
        symbols[address] = name
    return symbols


def collect_definition_counts(source_roots: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for root in source_roots:
        for path in root.rglob("*.c"):
            for match in FUNCTION_DEF_RE.finditer(load_text(path)):
                counts[match.group("name")] += 1
    return dict(counts)


def collect_fun_definition_counts(source_root: Path) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for path in source_root.rglob("*.c"):
        lines = load_text(path).splitlines()
        for index, line in enumerate(lines):
            match = FUN_REF_RE.search(line)
            if match and classify_role(lines, index) == "definition":
                counts[match.group("addr").lower()] += 1
    return dict(counts)


def classify_role(lines: list[str], index: int) -> str:
    line_text = lines[index]
    stripped = line_text.strip()
    if stripped.startswith("* Function:"):
        return "comment"
    if stripped.startswith("extern "):
        return "extern"
    if "{" in stripped and not stripped.startswith("if "):
        return "definition"
    for next_line in lines[index + 1 : index + 4]:
        next_stripped = next_line.strip()
        if not next_stripped:
            continue
        if next_stripped == "{":
            return "definition"
        break
    return "reference"


def collect_candidates(
    source_root: Path,
    symbols: dict[str, str],
    definition_counts: dict[str, int],
    fun_definition_counts: dict[str, int],
    ignored_names: set[str],
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for path in source_root.rglob("*.c"):
        text = load_text(path)
        lines = text.splitlines()
        for index, line in enumerate(lines, start=1):
            for match in FUN_REF_RE.finditer(line):
                address = match.group("addr").lower()
                target_name = symbols.get(address)
                if target_name is None or target_name in ignored_names:
                    continue
                has_target = re.search(r"\b" + re.escape(target_name) + r"\b", text) is not None
                candidates.append(
                    Candidate(
                        address=address,
                        target_name=target_name,
                        path=path,
                        line=index,
                        role=classify_role(lines, index - 1),
                        has_target_in_file=has_target,
                        target_definition_count=definition_counts.get(target_name, 0),
                        same_address_definition_count=fun_definition_counts.get(address, 0),
                    )
                )
    return sorted(
        candidates,
        key=lambda item: (
            item.risk,
            item.address,
            str(item.path).lower(),
            item.line,
            item.role,
        ),
    )


def format_markdown(candidates: list[Candidate], repo_root: Path) -> str:
    by_risk: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        by_risk[candidate.risk].append(candidate)

    lines = ["# Semantic name candidates", ""]
    lines.append(f"- candidates: `{len(candidates)}`")
    for risk in ("rename-ref", "rename-body", "multi-body", "defined-elsewhere", "same-file"):
        lines.append(f"- {risk}: `{len(by_risk.get(risk, ()))}`")
    lines.append("")

    for risk in ("rename-ref", "rename-body", "multi-body", "defined-elsewhere", "same-file"):
        entries = by_risk.get(risk, [])
        if not entries:
            continue
        lines.append(f"## {risk}")
        for entry in entries:
            rel_path = display_path(entry.path, repo_root)
            lines.append(
                f"- `0x{entry.address}` `{entry.target_name}` "
                f"`{rel_path}:{entry.line}` role=`{entry.role}` "
                f"defs=`{entry.target_definition_count}` "
                f"addr_defs=`{entry.same_address_definition_count}`"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def display_path(path: Path, repo_root: Path) -> str:
    if not path.is_absolute():
        return path.as_posix()
    return path.relative_to(repo_root).as_posix()


def write_csv(candidates: list[Candidate], repo_root: Path) -> None:
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        [
            "risk",
            "address",
            "target_name",
            "path",
            "line",
            "role",
            "target_definition_count",
            "same_address_definition_count",
        ]
    )
    for entry in candidates:
        writer.writerow(
            [
                entry.risk,
                f"0x{entry.address}",
                entry.target_name,
                display_path(entry.path, repo_root),
                entry.line,
                entry.role,
                entry.target_definition_count,
                entry.same_address_definition_count,
            ]
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Report FUN_<addr> references whose current EN address has a named "
            "symbol, while flagging likely duplicate-definition traps."
        )
    )
    parser.add_argument("--symbols", default="config/GSAE01/symbols.txt", type=Path)
    parser.add_argument("--source-root", default="src/main", type=Path)
    parser.add_argument(
        "--definition-root",
        action="append",
        default=None,
        type=Path,
        help="Roots to scan for existing C function definitions. Defaults to src.",
    )
    parser.add_argument(
        "--ignore-name",
        action="append",
        default=[],
        help="Additional symbol names to suppress.",
    )
    parser.add_argument("--format", choices=("markdown", "csv"), default="markdown")
    parser.add_argument(
        "--risk",
        action="append",
        choices=("rename-ref", "rename-body", "multi-body", "defined-elsewhere", "same-file"),
        help="Only show one or more risk buckets.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd()
    definition_roots = args.definition_root or [Path("src")]
    ignored_names = set(DEFAULT_IGNORED_NAMES)
    ignored_names.update(args.ignore_name)

    symbols = load_named_symbols(args.symbols)
    definition_counts = collect_definition_counts(definition_roots)
    fun_definition_counts = collect_fun_definition_counts(args.source_root)
    candidates = collect_candidates(
        args.source_root,
        symbols,
        definition_counts,
        fun_definition_counts,
        ignored_names,
    )
    if args.risk:
        wanted = set(args.risk)
        candidates = [candidate for candidate in candidates if candidate.risk in wanted]

    if args.format == "csv":
        write_csv(candidates, repo_root)
    else:
        sys.stdout.write(format_markdown(candidates, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
