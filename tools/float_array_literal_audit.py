#!/usr/bin/env python3
"""Audit one-element f32 constants that may be source-likely literals.

The decomp often models literal-pool floats as addressable arrays:

    const f32 gThing[1] = {1.0f};
    ... gThing[0] ...

For many TUs this is only a matching crutch.  Replacing those with macros or
plain literals is source-likely only when MWCC's resulting first-use pool order
still matches retail.  This tool does not edit files; it ranks candidates and
flags obvious order risks before a compile/prove pass.
"""

from __future__ import annotations

import argparse
from collections import Counter
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (ROOT / "src", ROOT / "include")
DEF_RE = re.compile(
    r"^(?P<prefix>\s*(?:static\s+)?const\s+f32\s+)"
    r"(?P<name>[A-Za-z_]\w*)\s*\[\s*1\s*\]\s*=\s*\{\s*(?P<value>[^}]+?)\s*\}\s*;"
)


@dataclass(frozen=True)
class FloatArrayDef:
    path: Path
    line: int
    name: str
    value: str
    is_static: bool
    indexed_uses: int
    bare_uses: int
    external_refs: int
    first_use_line: int | None

    @property
    def rel(self) -> str:
        return self.path.relative_to(ROOT).as_posix()

    @property
    def status(self) -> str:
        if self.external_refs:
            return "extern-risk"
        if self.bare_uses:
            return "address-risk"
        if self.indexed_uses == 0:
            return "unused"
        return "candidate"


def iter_text_files() -> list[Path]:
    paths: list[Path] = []
    for root in SOURCE_ROOTS:
        paths.extend(p for p in root.rglob("*") if p.suffix in {".c", ".h"})
    return sorted(paths)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


TOKEN_RE = re.compile(r"\b[A-Za-z_]\w*\b")


def token_index(texts: dict[Path, str]) -> tuple[Counter[str], dict[Path, Counter[str]]]:
    total: Counter[str] = Counter()
    by_path: dict[Path, Counter[str]] = {}
    for path, text in texts.items():
        counts = Counter(TOKEN_RE.findall(text))
        by_path[path] = counts
        total.update(counts)
    return total, by_path


def owner_uses(name: str, owner_text: str, def_line: int) -> tuple[int, int, int | None]:
    indexed = re.compile(rf"\b{re.escape(name)}\s*\[\s*0\s*\]")
    token = re.compile(rf"\b{re.escape(name)}\b")

    indexed_spans = list(indexed.finditer(owner_text))
    indexed_offsets = {span for m in indexed_spans for span in range(m.start(), m.end())}

    bare = 0
    first_use: int | None = None
    for m in token.finditer(owner_text):
        line = line_for_offset(owner_text, m.start())
        if line == def_line:
            continue
        if first_use is None:
            first_use = line
        if not all(i in indexed_offsets for i in range(m.start(), m.end())):
            bare += 1

    return len(indexed_spans), bare, first_use


def collect() -> list[FloatArrayDef]:
    texts = {path: read(path) for path in iter_text_files()}
    total_tokens, path_tokens = token_index(texts)
    defs: list[FloatArrayDef] = []
    for path, text in texts.items():
        for line_no, line in enumerate(text.splitlines(), 1):
            m = DEF_RE.match(line)
            if not m:
                continue
            name = m.group("name")
            indexed, bare, first_use = owner_uses(name, text, line_no)
            defs.append(
                FloatArrayDef(
                    path=path,
                    line=line_no,
                    name=name,
                    value=m.group("value").strip(),
                    is_static="static" in m.group("prefix"),
                    indexed_uses=indexed,
                    bare_uses=bare,
                    external_refs=total_tokens[name] - path_tokens[path][name],
                    first_use_line=first_use,
                )
            )
    return defs


def print_markdown(defs: list[FloatArrayDef], only_candidates: bool) -> None:
    rows = [d for d in defs if not only_candidates or d.status == "candidate"]
    by_file: dict[Path, list[FloatArrayDef]] = {}
    for d in rows:
        by_file.setdefault(d.path, []).append(d)

    print("# f32[1] Literal Audit")
    print()
    print(f"- definitions: `{len(defs)}`")
    print(f"- shown: `{len(rows)}`")
    print()
    for path in sorted(by_file):
        group = by_file[path]
        order = sorted(group, key=lambda d: d.line)
        first_use = sorted(
            (d for d in group if d.first_use_line is not None),
            key=lambda d: (d.first_use_line or 0, d.line),
        )
        first_use_names = [d.name for d in first_use]
        decl_names = [d.name for d in order if d.first_use_line is not None]
        order_risk = decl_names != first_use_names
        risk = " order-risk" if order_risk else ""
        print(f"## `{path.relative_to(ROOT).as_posix()}`{risk}")
        for d in order:
            first = "-" if d.first_use_line is None else str(d.first_use_line)
            storage = "static " if d.is_static else ""
            print(
                f"- `{d.status}` line `{d.line}` first-use `{first}` "
                f"{storage}`{d.name}` = `{d.value}` "
                f"uses=`{d.indexed_uses}` bare=`{d.bare_uses}` external=`{d.external_refs}`"
            )
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", action="store_true", help="show only low-obvious-risk definitions")
    args = parser.parse_args()
    print_markdown(collect(), args.candidates)


if __name__ == "__main__":
    main()
