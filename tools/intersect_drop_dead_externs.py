#!/usr/bin/env python3
"""Drop unused `extern undefined* (DAT|lbl)_xxx;` lines from intersect.c.

Only deletes a line if its symbol name appears nowhere else in the file —
i.e. the declaration is the sole reference. Keeps anything used in a body
or referenced by a narrower-typed alias below.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path("src/track/intersect.c")

DECL_RE = re.compile(
    r"^\s*extern\s+undefined\d?\s+(?P<name>(?:DAT|lbl)_[0-9A-Fa-f]+)\s*;\s*$"
)


def main() -> None:
    lines = SRC.read_text(encoding="utf-8").splitlines(keepends=True)
    full_text = "".join(lines)
    kept: list[str] = []
    dropped = 0
    for line in lines:
        m = DECL_RE.match(line)
        if m and full_text.count(m.group("name")) == 1:
            dropped += 1
            continue
        kept.append(line)
    SRC.write_text("".join(kept), encoding="utf-8")
    print(f"dropped {dropped} dead extern declarations")


if __name__ == "__main__":
    main()
