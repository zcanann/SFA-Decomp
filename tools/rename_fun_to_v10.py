from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


BLOCK_RE = re.compile(
    r"/\*\s*\r?\n\s*\* --INFO--\s*\r?\n\s*\*\s*\r?\n\s*\* Function:\s*(?P<function>FUN_[0-9A-Fa-f]+)"
    r".*?\r?\n\s*\* EN v1\.0 Address:\s*(?P<v10_addr>0x[0-9A-Fa-f]+)",
    re.S,
)
FUN_TOKEN_RE = re.compile(r"\bFUN_[0-9A-Fa-f]{8}\b")

# Known source-ownership conflicts where the v1.0 address already belongs to a
# recovered semantic owner in another corridor, so the placeholder should not
# be retargeted automatically.
SKIP_MAPPINGS = {
    "FUN_80270650": "FUN_8026fca0",
}


def iter_source_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.c") if path.is_file())


def iter_target_files(include_symbols: bool) -> list[Path]:
    targets: list[Path] = []
    for base in (Path("src"), Path("include")):
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in {".c", ".h"}:
                targets.append(path)
    if include_symbols:
        targets.append(Path("config/GSAE01/symbols.txt"))
    return sorted(targets)


def build_mapping() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for path in iter_source_files(Path("src")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in BLOCK_RE.finditer(text):
            old_name = match.group("function")
            new_name = f"FUN_{match.group('v10_addr')[2:].lower()}"
            if SKIP_MAPPINGS.get(old_name) == new_name:
                continue
            if old_name != new_name:
                mapping[old_name] = new_name
    return mapping


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rename drifting FUN_<addr> identifiers to their current EN v1.0 addresses."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report pending replacements without modifying files.",
    )
    parser.add_argument(
        "--include-symbols",
        action="store_true",
        help="Also rewrite config/GSAE01/symbols.txt.",
    )
    args = parser.parse_args()

    targets = iter_target_files(args.include_symbols)
    target_texts = {
        path: path.read_text(encoding="utf-8", errors="ignore")
        for path in targets
    }

    mapping = build_mapping()
    usage = Counter(
        token
        for text in target_texts.values()
        for token in FUN_TOKEN_RE.findall(text)
    )

    safe_mapping: dict[str, str] = {}
    skipped_collisions: list[tuple[str, str]] = []
    for old_name, new_name in sorted(mapping.items()):
        if usage.get(new_name, 0) != 0 and new_name not in mapping:
            skipped_collisions.append((old_name, new_name))
            continue
        safe_mapping[old_name] = new_name

    if not safe_mapping:
        print("no safe mappings found")
        return 0

    token_re = re.compile(
        r"\b(" + "|".join(re.escape(name) for name in sorted(safe_mapping, key=len, reverse=True)) + r")\b"
    )

    files_changed = 0
    replacements = 0
    for path, original in target_texts.items():
        file_replacements = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal file_replacements, replacements
            old_name = match.group(0)
            new_name = safe_mapping.get(old_name)
            if new_name is None:
                return old_name
            file_replacements += 1
            replacements += 1
            return new_name

        updated = token_re.sub(replace, original)
        if file_replacements == 0:
            continue

        files_changed += 1
        if not args.check:
            path.write_text(updated, encoding="utf-8", newline="")

    mode = "would update" if args.check else "updated"
    print(f"candidate_mappings={len(mapping)}")
    print(f"safe_mappings={len(safe_mapping)} skipped_collisions={len(skipped_collisions)}")
    print(f"{mode} {replacements} replacements across {files_changed} files")
    if skipped_collisions:
        print("collision_samples:")
        for old_name, new_name in skipped_collisions[:10]:
            print(f"  {old_name} -> {new_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
