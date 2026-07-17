#!/usr/bin/env python3
"""List type definitions relevant to one function and retrieve full definitions.

Inside an sfa-harness workspace the target is read from
``.decomp-harness/target.json`` automatically:

    python3 tools/symbol_context.py relevant
    python3 tools/symbol_context.py get ModelLightStruct

For manual use, pass ``--source``, ``--function``, and optionally ``--context``.
The index is deliberately source-backed and read-only; it scans ``include/`` and
``src/`` and uses the target's generated ``.ctx`` to report definition visibility.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_METADATA = REPO_ROOT / ".decomp-harness/target.json"
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")
COMPOUND_RE = re.compile(
    r"\btypedef\s+(struct|union|enum)\s+([A-Za-z_]\w*)?\s*\{"
    r"|\b(struct|union|enum)\s+([A-Za-z_]\w*)\s*\{"
)
TYPEDEF_RE = re.compile(r"\btypedef\b")


@dataclass(frozen=True)
class Target:
    source: Path | None
    function: str | None
    context: Path | None


@dataclass(frozen=True)
class Definition:
    names: tuple[str, ...]
    kind: str
    path: str
    line: int
    text: str
    has_body: bool


def _resolve_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def _target_from_args(args: argparse.Namespace, *, require_function: bool) -> Target:
    metadata = {}
    if TARGET_METADATA.is_file():
        metadata = json.loads(TARGET_METADATA.read_text(encoding="utf-8"))
    source = _resolve_path(args.source or metadata.get("source_path"))
    function = getattr(args, "function", None) or metadata.get("symbol")
    context = _resolve_path(args.context or metadata.get("context_path"))
    if require_function and (source is None or not function):
        raise SystemExit(
            "target unavailable; run inside a harness workspace or pass "
            "--source and --function"
        )
    return Target(source=source, function=function, context=context)


def _mask_noncode(text: str) -> str:
    """Replace comments and quoted contents with spaces while preserving offsets."""
    out = list(text)
    state = "code"
    i = 0
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = "line"
                i += 2
                continue
            if char == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                state = "block"
                i += 2
                continue
            if char == '"':
                out[i] = " "
                state = "string"
            elif char == "'":
                out[i] = " "
                state = "char"
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if char == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 2
                continue
            if char != "\n":
                out[i] = " "
        else:
            if char == "\\" and nxt:
                out[i] = " "
                if nxt != "\n":
                    out[i + 1] = " "
                i += 2
                continue
            if (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
            if char != "\n":
                out[i] = " "
        i += 1
    return "".join(out)


def _matching_delimiter(masked: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(masked)):
        if masked[index] == opening:
            depth += 1
        elif masked[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _typedef_aliases(masked_tail: str) -> list[str]:
    aliases = []
    for part in masked_tail.split(","):
        pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)", part)
        if pointer:
            aliases.append(pointer.group(1))
            continue
        match = re.search(
            r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*(?:ATTRIBUTE_[A-Z_]+\s*\([^)]*\)\s*)?$",
            part.strip(),
        )
        if match:
            aliases.append(match.group(1))
    return aliases


def _split_top_level_commas(text: str) -> list[str]:
    parts = []
    start = 0
    parens = brackets = 0
    for index, char in enumerate(text):
        if char == "(":
            parens += 1
        elif char == ")":
            parens = max(0, parens - 1)
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets = max(0, brackets - 1)
        elif char == "," and parens == 0 and brackets == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _simple_typedef_aliases(masked_body: str) -> list[str]:
    pointer_names = re.findall(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", masked_body)
    if pointer_names:
        return pointer_names
    function_name = re.search(
        r"([A-Za-z_]\w*)\s*\([^;]*\)\s*$", masked_body.strip()
    )
    if function_name:
        return [function_name.group(1)]
    aliases = []
    for part in _split_top_level_commas(masked_body):
        match = re.search(
            r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$", part.strip()
        )
        if match:
            aliases.append(match.group(1))
    return aliases


def scan_definitions(text: str, path: str) -> list[Definition]:
    masked = _mask_noncode(text)
    definitions: list[Definition] = []
    compound_spans: list[tuple[int, int]] = []
    for match in COMPOUND_RE.finditer(masked):
        opening = masked.find("{", match.start(), match.end())
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing < 0:
            continue
        semicolon = masked.find(";", closing)
        if semicolon < 0:
            continue
        is_typedef = match.group(1) is not None
        kind = match.group(1) or match.group(3)
        tag = match.group(2) or match.group(4)
        names = [tag] if tag else []
        if is_typedef:
            names.extend(_typedef_aliases(masked[closing + 1 : semicolon]))
        unique_names = tuple(dict.fromkeys(name for name in names if name))
        if not unique_names:
            continue
        definitions.append(
            Definition(
                names=unique_names,
                kind=str(kind),
                path=path,
                line=text.count("\n", 0, match.start()) + 1,
                text=text[match.start() : semicolon + 1].strip(),
                has_body=True,
            )
        )
        compound_spans.append((match.start(), semicolon + 1))

    for match in TYPEDEF_RE.finditer(masked):
        if any(start <= match.start() < end for start, end in compound_spans):
            continue
        semicolon = masked.find(";", match.end())
        if semicolon < 0:
            continue
        body = masked[match.end() : semicolon]
        if "{" in body:
            continue
        aliases = _simple_typedef_aliases(body)
        if not aliases:
            continue
        definitions.append(
            Definition(
                names=tuple(dict.fromkeys(aliases)),
                kind="typedef",
                path=path,
                line=text.count("\n", 0, match.start()) + 1,
                text=text[match.start() : semicolon + 1].strip(),
                has_body=False,
            )
        )
    return definitions


def _source_paths() -> Iterable[Path]:
    for root in (REPO_ROOT / "include", REPO_ROOT / "src"):
        if root.is_dir():
            yield from sorted(
                path for path in root.rglob("*") if path.suffix in {".h", ".c", ".cp"}
            )


def build_index(target: Target) -> tuple[dict[str, list[Definition]], dict[str, list[Definition]]]:
    index: dict[str, list[Definition]] = {}
    for path in _source_paths():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(REPO_ROOT))
        for definition in scan_definitions(text, relative):
            for name in definition.names:
                index.setdefault(name, []).append(definition)

    context_index: dict[str, list[Definition]] = {}
    if target.context and target.context.is_file():
        text = target.context.read_text(encoding="utf-8", errors="replace")
        for definition in scan_definitions(text, str(target.context.relative_to(REPO_ROOT))):
            for name in definition.names:
                context_index.setdefault(name, []).append(definition)
                index.setdefault(name, []).append(definition)
    return index, context_index


def _normalized_definition(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _interesting_definition(definition: Definition) -> bool:
    if definition.has_body:
        return True
    return bool(
        re.search(r"\b(?:struct|union|enum)\b|\(\s*\*|\[", definition.text)
    )


def _is_forward_declaration(definition: Definition) -> bool:
    return not definition.has_body and bool(
        re.fullmatch(
            r"typedef\s+(?:struct|union|enum)\s+([A-Za-z_]\w*)\s+\1\s*;",
            _normalized_definition(definition.text),
        )
    )


def interesting_type_names(index: dict[str, list[Definition]]) -> set[str]:
    names = {
        name
        for name, definitions in index.items()
        if any(_interesting_definition(item) for item in definitions)
    }
    changed = True
    while changed:
        changed = False
        for name, definitions in index.items():
            if name in names:
                continue
            for definition in definitions:
                dependencies = set(IDENTIFIER_RE.findall(definition.text)) - {
                    "typedef",
                    name,
                }
                if dependencies & names:
                    names.add(name)
                    changed = True
                    break
    return names


def _definition_visible(definition: Definition, context_defs: list[Definition]) -> bool:
    wanted = _normalized_definition(definition.text)
    return any(
        item.has_body == definition.has_body
        and _normalized_definition(item.text) == wanted
        for item in context_defs
    )


def _deduplicate_definitions(
    definitions: list[Definition], context_defs: list[Definition], target: Target
) -> list[Definition]:
    by_text: dict[str, Definition] = {}
    source_path = (
        str(target.source.relative_to(REPO_ROOT))
        if target.source and target.source.is_relative_to(REPO_ROOT)
        else None
    )
    for definition in definitions:
        key = _normalized_definition(definition.text)
        current = by_text.get(key)
        if current is None:
            by_text[key] = definition
            continue
        current_rank = (
            current.path.startswith("build/"),
            current.path != source_path,
        )
        candidate_rank = (
            definition.path.startswith("build/"),
            definition.path != source_path,
        )
        if candidate_rank < current_rank:
            by_text[key] = definition
    return list(by_text.values())


def choose_definition(
    name: str,
    index: dict[str, list[Definition]],
    context_index: dict[str, list[Definition]],
    target: Target,
    path_filter: str | None = None,
) -> Definition:
    candidates = _deduplicate_definitions(
        index.get(name, []), context_index.get(name, []), target
    )
    if path_filter:
        candidates = [item for item in candidates if item.path == path_filter]
    if not candidates:
        raise LookupError(f"no type definition found for {name}")

    source_path = (
        str(target.source.relative_to(REPO_ROOT))
        if target.source and target.source.is_relative_to(REPO_ROOT)
        else None
    )

    def rank(item: Definition) -> tuple:
        is_visible = _definition_visible(item, context_index.get(name, []))
        if is_visible and not _is_forward_declaration(item):
            definition_class = 0
        elif item.has_body:
            definition_class = 1
        elif is_visible:
            definition_class = 2
        else:
            definition_class = 3
        return (
            definition_class,
            item.path != source_path,
            not item.path.startswith("include/"),
        )

    candidates.sort(key=lambda item: (*rank(item), item.path, item.line))
    best_rank = rank(candidates[0])
    best = [item for item in candidates if rank(item) == best_rank]
    if len(best) > 1:
        choices = "\n".join(f"  {item.path}:{item.line}" for item in best)
        raise LookupError(
            f"ambiguous type definition for {name}; pass --path with one of:\n{choices}"
        )
    return best[0]


def extract_function(text: str, symbol: str) -> str | None:
    masked = _mask_noncode(text)
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\s*\(")
    for match in pattern.finditer(masked):
        opening = masked.find("(", match.start(), match.end())
        closing = _matching_delimiter(masked, opening, "(", ")")
        if closing < 0:
            continue
        brace = masked.find("{", closing)
        semicolon = masked.find(";", closing)
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        body_end = _matching_delimiter(masked, brace, "{", "}")
        if body_end < 0:
            continue
        prior_semicolon = masked.rfind(";", 0, match.start())
        prior_brace = masked.rfind("}", 0, match.start())
        start = max(prior_semicolon, prior_brace) + 1
        return text[start : body_end + 1].strip()
    return None


def visibility(name: str, context_index: dict[str, list[Definition]]) -> str:
    definitions = context_index.get(name, [])
    if any(not _is_forward_declaration(item) for item in definitions):
        return "full"
    if definitions:
        return "forward"
    return "no"


def command_relevant(args: argparse.Namespace) -> int:
    target = _target_from_args(args, require_function=True)
    assert target.source is not None and target.function is not None
    if not target.source.is_file():
        raise SystemExit(f"source does not exist: {target.source}")
    function = extract_function(
        target.source.read_text(encoding="utf-8", errors="replace"), target.function
    )
    if function is None:
        raise SystemExit(f"function definition not found: {target.function}")

    index, context_index = build_index(target)
    interesting_names = interesting_type_names(index)
    direct = sorted(set(IDENTIFIER_RE.findall(function)) & interesting_names)
    depths = {name: 0 for name in direct}
    queue = list(direct)
    while queue:
        name = queue.pop(0)
        depth = depths[name]
        if depth >= args.depth:
            continue
        try:
            definition = choose_definition(name, index, context_index, target)
        except LookupError:
            continue
        dependencies = set(IDENTIFIER_RE.findall(definition.text)) & interesting_names
        for dependency in sorted(dependencies - set(depths)):
            depths[dependency] = depth + 1
            queue.append(dependency)

    rows = []
    for name, depth in depths.items():
        try:
            definition = choose_definition(name, index, context_index, target)
        except LookupError:
            continue
        rows.append((depth, name, definition))
    rows.sort(key=lambda row: (row[0], row[1]))
    print(f"[{len(rows)} relevant type(s) for {target.function}; direct first]")
    print("RELATION      VISIBILITY  KIND     NAME  DEFINITION")
    for depth, name, definition in rows[: args.limit]:
        relation = "direct" if depth == 0 else f"transitive:{depth}"
        print(
            f"{relation:13s} {visibility(name, context_index):10s}  "
            f"{definition.kind:7s}  {name}  {definition.path}:{definition.line}"
        )
    if len(rows) > args.limit:
        print(f"... +{len(rows)-args.limit} more (raise --limit)")
    if rows:
        print("\nRetrieve one with: python3 tools/symbol_context.py get NAME")
    return 0


def command_get(args: argparse.Namespace) -> int:
    target = _target_from_args(args, require_function=False)
    index, context_index = build_index(target)
    try:
        definition = choose_definition(
            args.name, index, context_index, target, path_filter=args.path
        )
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        f"{args.name}  {definition.kind}  {definition.path}:{definition.line}  "
        f"visibility={visibility(args.name, context_index)}"
    )
    print(definition.text)
    return 0


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", help="target source path (defaults to harness metadata)")
    parser.add_argument("--context", help="target .ctx path (defaults to harness metadata)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    relevant = subparsers.add_parser("relevant", help="list types used by the target function")
    _add_target_options(relevant)
    relevant.add_argument("--function", help="target function (defaults to harness metadata)")
    relevant.add_argument("--depth", type=int, default=2, help="transitive type depth (default 2)")
    relevant.add_argument("--limit", type=int, default=50)
    relevant.set_defaults(handler=command_relevant)

    get = subparsers.add_parser("get", help="print one complete type definition")
    get.add_argument("name")
    _add_target_options(get)
    get.add_argument("--path", help="definition path when the name is ambiguous")
    get.set_defaults(handler=command_get)

    args = parser.parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
