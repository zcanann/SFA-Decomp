from __future__ import annotations

import argparse
import re
from pathlib import Path


BLOCK_RE = re.compile(
    r"(?P<v10_addr>^\s*\* EN v1\.0 Address:\s*)(?P<v10_addr_value>[^\r\n]+)(?P<v10_addr_nl>\r?\n)"
    r"(?P<v10_size>^\s*\* EN v1\.0 Size:\s*)(?P<v10_size_value>[^\r\n]+)(?P<v10_size_nl>\r?\n)"
    r"(?P<v11_addr>^\s*\* EN v1\.1 Address:\s*)(?P<v11_addr_value>[^\r\n]+)(?P<v11_addr_nl>\r?\n)"
    r"(?P<v11_size>^\s*\* EN v1\.1 Size:\s*)(?P<v11_size_value>[^\r\n]+)",
    re.MULTILINE,
)


def transform_text(text: str) -> tuple[str, int]:
    changed = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal changed

        v10_addr_value = match.group("v10_addr_value").strip()
        v10_size_value = match.group("v10_size_value").strip()
        v11_addr_value = match.group("v11_addr_value").strip()
        v11_size_value = match.group("v11_size_value").strip()

        if v10_addr_value == "TODO" and v10_size_value == "TODO":
            return match.group(0)

        if v11_addr_value != "TODO" or v11_size_value != "TODO":
            return match.group(0)

        changed += 1
        return (
            f"{match.group('v10_addr')}TODO{match.group('v10_addr_nl')}"
            f"{match.group('v10_size')}TODO{match.group('v10_size_nl')}"
            f"{match.group('v11_addr')}{v10_addr_value}{match.group('v11_addr_nl')}"
            f"{match.group('v11_size')}{v10_size_value}"
        )

    return BLOCK_RE.sub(replace, text), changed


def iter_source_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.c") if path.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Move populated EN v1.0 function-comment metadata into the EN v1.1 fields."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("src"),
        help="Root directory to scan (default: src)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report how many blocks would change without modifying files.",
    )
    args = parser.parse_args()

    files_changed = 0
    blocks_changed = 0

    for path in iter_source_files(args.root):
        original = path.read_text(encoding="utf-8", errors="ignore")
        updated, changed = transform_text(original)
        if changed == 0:
            continue

        files_changed += 1
        blocks_changed += changed

        if not args.check:
            path.write_text(updated, encoding="utf-8", newline="")

    mode = "would update" if args.check else "updated"
    print(f"{mode} {blocks_changed} blocks across {files_changed} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
