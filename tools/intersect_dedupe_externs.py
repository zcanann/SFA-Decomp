#!/usr/bin/env python3
"""Drop `extern undefined* SYM;` declarations whose symbol is later
declared with a stronger type (e.g. `extern u8 SYM[];` or `extern s32 SYM;`)
in the same file. Run this after dropping dead externs and before renaming
DAT_xxx → lbl_xxx so there are no type-conflict redeclarations.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path("src/track/intersect.c")

UNDEF_RE = re.compile(
    r"^\s*extern\s+undefined\d?\s*\*?\s+(?P<name>(?:DAT|lbl)_[0-9A-Fa-f]+)\s*;\s*$"
)
ANY_DECL_RE = re.compile(
    r"^\s*extern\s+(?P<type>[^\s;].*?)\s+(?P<name>(?:DAT|lbl)_[0-9A-Fa-f]+)(?:\[\])?\s*;\s*$"
)


def main() -> None:
    lines = SRC.read_text(encoding="utf-8").splitlines(keepends=True)

    # collect every declared symbol with the type used and the line number
    decls: dict[str, list[tuple[int, str]]] = {}
    for idx, line in enumerate(lines):
        m = ANY_DECL_RE.match(line)
        if not m:
            continue
        decls.setdefault(m.group("name"), []).append((idx, m.group("type").strip()))

    drop_lines: set[int] = set()
    for name, items in decls.items():
        if len(items) <= 1:
            continue
        types = [t for _, t in items]
        # if at least one declaration uses something stronger than `undefined*`,
        # drop the undefined* ones.
        weak = {t for t in types if re.fullmatch(r"undefined\d?\*?", t)}
        strong = [t for t in types if t not in weak]
        if weak and strong:
            for idx, t in items:
                if t in weak:
                    drop_lines.add(idx)

    if not drop_lines:
        print("nothing to drop")
        return

    out = [line for idx, line in enumerate(lines) if idx not in drop_lines]
    SRC.write_text("".join(out), encoding="utf-8")
    print(f"dropped {len(drop_lines)} weak-typed extern declarations")


if __name__ == "__main__":
    main()
