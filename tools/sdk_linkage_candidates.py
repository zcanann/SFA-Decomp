from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SDK_PREFIXES = ("dolphin/", "Runtime.PPCEABI.H/")


@dataclass(frozen=True)
class Candidate:
    path: str
    code_percent: float | None
    data_percent: float | None
    text_size: int
    bad_symbols: int
    active_unit: bool
    error: str | None = None


def object_suffix(source: str) -> str:
    return str(Path(source).with_suffix(".o")).replace("\\", "/")


def has_active_unit(version: str, source: str) -> bool:
    config_path = REPO_ROOT / "build" / version / "config.json"
    if not config_path.is_file():
        return False

    units = json.loads(config_path.read_text()).get("units", [])
    suffix = f"/obj/{object_suffix(source)}"
    for unit in units:
        obj = unit.get("object", "").replace("\\", "/")
        if obj.endswith(suffix):
            return True
    return False


def object_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"Object\(\s*NonMatching\s*,", text):
        start = match.start()
        depth = 0
        in_string = False
        escape = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    blocks.append(text[start : index + 1])
                    break
    return blocks


def parse_nonmatching_objects(configure: Path, include_game_classified: bool = False) -> list[str]:
    text = configure.read_text()
    paths: list[str] = []
    for block in object_blocks(text):
        match = re.search(r'Object\(\s*NonMatching\s*,\s*"([^"]+)"', block, re.DOTALL)
        if not match:
            continue
        path = match.group(1)
        if not include_game_classified and re.search(r'progress_category\s*=\s*"game"', block):
            continue
        if path.startswith(SDK_PREFIXES):
            paths.append(path)
    return paths


def object_path(root: Path, version: str, kind: str, source: str) -> Path:
    return root / "build" / version / kind / Path(source).with_suffix(".o")


def section_min(diff: dict, kinds: set[str]) -> float | None:
    values: list[float] = []
    for section in diff.get("left", {}).get("sections", []):
        if section.get("kind") in kinds and section.get("match_percent") is not None:
            values.append(float(section["match_percent"]))
    return min(values) if values else None


def text_size(diff: dict) -> int:
    total = 0
    for section in diff.get("left", {}).get("sections", []):
        if section.get("kind") == "SECTION_CODE":
            total += int(section.get("size", "0"))
    return total


def bad_symbol_count(diff: dict) -> int:
    count = 0
    for symbol in diff.get("left", {}).get("symbols", []):
        if symbol.get("match_percent") is not None and float(symbol["match_percent"]) < 100.0:
            count += 1
    return count


def diff_candidate(args: argparse.Namespace, source: str) -> Candidate | None:
    active_unit = has_active_unit(args.version, source)
    if args.active_only and not active_unit:
        return None

    src_obj = object_path(REPO_ROOT, args.version, "src", source)
    base_obj = object_path(REPO_ROOT, args.version, "obj", source)
    if not src_obj.exists() or not base_obj.exists():
        return None

    cmd = [
        str(REPO_ROOT / "tools" / "objdiff-cli.exe"),
        "diff",
        "-1",
        str(src_obj),
        "-2",
        str(base_obj),
        "-o",
        "-",
        "--format",
        "json",
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        return Candidate(source, None, None, 0, 0, active_unit, proc.stderr.strip())

    diff = json.loads(proc.stdout)
    return Candidate(
        path=source,
        code_percent=section_min(diff, {"SECTION_CODE"}),
        data_percent=section_min(diff, {"SECTION_DATA", "SECTION_RODATA", "SECTION_BSS"}),
        text_size=text_size(diff),
        bad_symbols=bad_symbol_count(diff),
        active_unit=active_unit,
    )


def format_percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:6.2f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rank NonMatching SDK source objects by direct objdiff against extracted original objects."
    )
    parser.add_argument("-v", "--version", default="GSAE01", help="Target version (default: GSAE01)")
    parser.add_argument("--min-code", type=float, default=0.0, help="Minimum code match percent to print")
    parser.add_argument("--limit", type=int, default=50, help="Maximum rows to print")
    parser.add_argument("--active-only", action="store_true", help="Only print candidates present in the build config")
    parser.add_argument("--show-errors", action="store_true", help="Print objdiff failures")
    parser.add_argument(
        "--include-game-classified",
        action="store_true",
        help="Also include SDK-looking paths whose Object entry is explicitly progress_category='game'",
    )
    args = parser.parse_args()

    sources = parse_nonmatching_objects(
        REPO_ROOT / "configure.py",
        include_game_classified=args.include_game_classified,
    )
    candidates = [c for source in sources if (c := diff_candidate(args, source)) is not None]
    candidates.sort(
        key=lambda c: (
            c.code_percent is not None,
            c.code_percent or -1.0,
            c.data_percent if c.data_percent is not None else 101.0,
            c.text_size,
        ),
        reverse=True,
    )

    printed = 0
    for candidate in candidates:
        if candidate.error:
            if args.show_errors:
                print(f"error path={candidate.path} {candidate.error}")
            continue
        if candidate.code_percent is not None and candidate.code_percent < args.min_code:
            continue
        print(
            f"code={format_percent(candidate.code_percent)} "
            f"data={format_percent(candidate.data_percent)} "
            f"text=0x{candidate.text_size:X} "
            f"bad-symbols={candidate.bad_symbols:2d} "
            f"active={'yes' if candidate.active_unit else 'no '} "
            f"path={candidate.path}"
        )
        printed += 1
        if printed >= args.limit:
            break


if __name__ == "__main__":
    main()
