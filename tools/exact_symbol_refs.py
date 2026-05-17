#!/usr/bin/env python3
"""Find raw FUN_ references that have named symbols at the same address."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


SYMBOL_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*) = \.text:0x([0-9A-Fa-f]{8}); // type:function"
)
FUN_RE = re.compile(r"\bFUN_([0-9A-Fa-f]{8})\b")
AUTO_NAME_RE = re.compile(r"^(FUN|fn|lbl|__|_)")


DEFAULT_SKIP_REASONS = {
    # Known noisy or duplicated/boundary-sensitive hits. Use --no-default-skip
    # when revisiting one after its neighboring split/window has been repaired.
    "8007e77c": "maketex save callback window is much larger than symbol",
    "8010daf8": "raw reference lands inside CameraModeFixed_init",
    "801101dc": "CameraModeForceBehind has duplicate raw and named stubs",
    "8012eb7c": "GameUI item-use helper has duplicate raw and named bodies",
    "8013dc88": "trickyGrowl is named in dll_D1; dll_E2 hit is a duplicate window",
    "8013ffb8": "trickyGuard appears as duplicate raw and named bodies",
    "8014d9e4": "enemy_init live source is a stub before the recovered body window",
    "801847e8": "scarab_getExtraSize has duplicate raw windows",
    "801978a8": "lightning_free descriptor name conflicts with init-like live body",
    "801b3658": "dimlavasmash_init live source is only the stub at a larger symbol window start",
    "801b5650": "explosion_release has duplicate/boundary-sensitive ownership",
    "801cf0ac": "nw_mammoth_update live source is split into stub and following body windows",
    "801d1e24": "enemymushroom_update spans duplicate object windows",
    "801d80f4": "SH_LevelControl_setMusic appears in conflicting source windows",
    "801dafdc": "sh_emptytumblew_init live source window disagrees with the symbol window",
    "801e34c0": "SB_ShipGun_update appears in multiple duplicate object windows",
    "801e42f8": "SB_FireBall_hitDetect appears at a boundary-sensitive TREX window",
    "801feb30": "dbegg_update spans duplicate expr/timer/anim ownership",
    "80209df0": "dfplightni_init source window is much smaller than symbol",
    "80247f54": "SeekTwiceBeforeRead symbol overlaps many vector-length callsites",
    "8028685c": "TRKNubMainLoop aliases unresolved game callsites; verify SDK ownership first",
    "80286990": "TRKPostEvent aliases arithmetic-looking game callsites; verify SDK ownership first",
}


def load_symbols(symbols_path: Path) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for line in symbols_path.read_text().splitlines():
        match = SYMBOL_RE.match(line)
        if match is None:
            continue
        name, address = match.groups()
        if not AUTO_NAME_RE.match(name):
            symbols[address.lower()] = name
    return symbols


def collect_named_definitions(root: Path, include_autos: bool) -> dict[str, set[Path]]:
    definitions: dict[str, set[Path]] = {}
    definition_re = re.compile(
        r"\b(?:void|int|uint|undefined\d*|double|float|char|bool)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
    )
    for path in root.rglob("*.c"):
        rel = path.as_posix()
        if not include_autos and "unknown/autos" in rel:
            continue
        for line in path.read_text(errors="ignore").splitlines():
            match = definition_re.search(line.strip())
            if match is None:
                continue
            name = match.group(1)
            if AUTO_NAME_RE.match(name):
                continue
            definitions.setdefault(name, set()).add(path)
    return definitions


def classify_line(stripped: str) -> str:
    if stripped.startswith("extern "):
        return "extern"
    if stripped.startswith("*") or stripped.startswith("//") or stripped.startswith("Function:"):
        return "comment"
    if re.search(r"\b(?:void|int|uint|undefined\d*|double|float|char|bool)\s+FUN_[0-9A-Fa-f]{8}\b", stripped):
        return "definition"
    return "live"


def iter_refs(
    root: Path,
    symbols: dict[str, str],
    include_autos: bool,
    skip: set[str],
    named_definitions: dict[str, set[Path]],
    include_duplicate_definitions: bool,
    include_unused_externs: bool,
):
    for path in root.rglob("*.c"):
        rel = path.as_posix()
        if not include_autos and "unknown/autos" in rel:
            continue
        text = path.read_text(errors="ignore")
        live_addresses: set[str] = set()
        if not include_unused_externs:
            for line in text.splitlines():
                if "FUN_" not in line:
                    continue
                kind = classify_line(line.strip())
                if kind in ("comment", "extern", "definition"):
                    continue
                live_addresses.update(match.group(1).lower() for match in FUN_RE.finditer(line))
        for lineno, line in enumerate(text.splitlines(), 1):
            if "FUN_" not in line:
                continue
            stripped = line.strip()
            kind = classify_line(stripped)
            if kind == "comment":
                continue
            for match in FUN_RE.finditer(line):
                address = match.group(1).lower()
                name = symbols.get(address)
                if name is None or address in skip or re.search(rf"\b{re.escape(name)}\b", text):
                    continue
                if kind == "extern" and not include_unused_externs and address not in live_addresses:
                    continue
                if (
                    kind == "definition"
                    and not include_duplicate_definitions
                    and any(named_path != path for named_path in named_definitions.get(name, set()))
                ):
                    continue
                yield kind, name, f"FUN_{address}", path, lineno, stripped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symbols", type=Path, default=Path("config/GSAE01/symbols.txt"))
    parser.add_argument("--root", type=Path, default=Path("src/main"))
    parser.add_argument(
        "--kind",
        choices=("all", "extern", "definition", "live"),
        default="all",
        help="filter by reference kind",
    )
    parser.add_argument("--include-autos", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="maximum rows to print; 0 means unlimited")
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        help="extra lowercase hex address or FUN_ address to suppress; repeatable",
    )
    parser.add_argument(
        "--no-default-skip",
        action="store_true",
        help="do not suppress the built-in noisy/boundary-sensitive addresses",
    )
    parser.add_argument(
        "--show-skips",
        action="store_true",
        help="print the built-in skip list with reasons and exit",
    )
    parser.add_argument(
        "--include-duplicate-definitions",
        action="store_true",
        help="include raw definitions even when a named definition exists in another source file",
    )
    parser.add_argument(
        "--include-unused-externs",
        action="store_true",
        help="include raw extern declarations that have no live use in the same file",
    )
    args = parser.parse_args()

    if args.show_skips:
        for address, reason in sorted(DEFAULT_SKIP_REASONS.items()):
            print(f"FUN_{address}: {reason}")
        return 0

    symbols = load_symbols(args.symbols)
    named_definitions = collect_named_definitions(args.root, args.include_autos)
    skip = set() if args.no_default_skip else set(DEFAULT_SKIP_REASONS)
    skip.update(item.lower().removeprefix("fun_") for item in args.skip)

    count = 0
    for kind, name, fun, path, lineno, line in iter_refs(
        args.root,
        symbols,
        args.include_autos,
        skip,
        named_definitions,
        args.include_duplicate_definitions,
        args.include_unused_externs,
    ):
        if args.kind != "all" and kind != args.kind:
            continue
        print(f"{kind:10} {name:32} {fun} {path}:{lineno}: {line[:180]}")
        count += 1
        if args.limit and count >= args.limit:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
