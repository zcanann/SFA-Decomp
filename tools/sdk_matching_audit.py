from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SDK_PREFIXES = ("dolphin/", "Runtime.PPCEABI.H/")


@dataclass(frozen=True)
class ConfigObject:
    status: str
    path: str


@dataclass(frozen=True)
class AuditResult:
    obj: ConfigObject
    code_percent: float | None
    data_percent: float | None
    text_size: int
    bad_symbols: int
    error: str | None = None
    skipped: str | None = None

    @property
    def ok(self) -> bool:
        values = [value for value in (self.code_percent, self.data_percent) if value is not None]
        return self.error is None and self.skipped is None and all(value == 100.0 for value in values)


def iter_object_calls(text: str) -> list[str]:
    calls: list[str] = []
    pos = 0
    while True:
        start = text.find("Object(", pos)
        if start < 0:
            break

        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    calls.append(text[start : i + 1])
                    pos = i + 1
                    break
        else:
            break
    return calls


def first_quoted_string(text: str) -> str | None:
    in_string = False
    escape = False
    start = 0
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                return text[start:i]
            continue
        if ch == '"':
            in_string = True
            start = i + 1
    return None


def split_top_level_args(text: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
    args.append(text[start:].strip())
    return args


def matching_sdk_objects(configure: Path) -> list[ConfigObject]:
    objects: list[ConfigObject] = []
    for call in iter_object_calls(configure.read_text()):
        body = call[len("Object(") :].lstrip()
        args = split_top_level_args(body[:-1])
        if len(args) < 2:
            continue
        status = args[0]
        if status.startswith("NonMatching"):
            continue
        if not (status.startswith("Matching") or status.startswith("MatchingFor")):
            continue

        path = first_quoted_string(args[1])
        if path is None or not path.startswith(SDK_PREFIXES):
            continue
        objects.append(ConfigObject(status, path))
    return objects


def object_path(version: str, kind: str, source: str) -> Path:
    return REPO_ROOT / "build" / version / kind / Path(source).with_suffix(".o")


def active_unit_names(version: str) -> set[str]:
    config_path = REPO_ROOT / "build" / version / "config.json"
    if not config_path.is_file():
        return set()
    data = json.loads(config_path.read_text())
    return {unit.get("name", "").replace("\\", "/") for unit in data.get("units", [])}


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


def has_target_payload(diff: dict) -> bool:
    for section in diff.get("right", {}).get("sections", []):
        if section.get("kind") in {"SECTION_CODE", "SECTION_DATA", "SECTION_RODATA", "SECTION_BSS"}:
            if int(section.get("size", "0")) > 0:
                return True
    return False


def binutils_tool(name: str) -> Path:
    exe = REPO_ROOT / "build" / "binutils" / f"{name}.exe"
    if exe.is_file():
        return exe
    return REPO_ROOT / "build" / "binutils" / name


def section_bytes(obj: Path, section: str, work_dir: Path) -> bytes | None:
    output = work_dir / f"{obj.stem}_{section.strip('.')}.bin"
    cmd = [
        str(binutils_tool("powerpc-eabi-objcopy")),
        "-O",
        "binary",
        "-j",
        section,
        str(obj),
        str(output),
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0 or not output.is_file():
        return None
    return output.read_bytes()


def relocation_width(reloc_type: str) -> int:
    if "16" in reloc_type:
        return 2
    return 4


def source_relocation_bytes(obj: Path, section: str) -> set[int]:
    cmd = [str(binutils_tool("powerpc-eabi-objdump")), "-r", str(obj)]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        return set()

    covered: set[int] = set()
    active_section: str | None = None
    header = "RELOCATION RECORDS FOR ["
    for line in proc.stdout.splitlines():
        if line.startswith(header):
            active_section = line[len(header) :].split("]", 1)[0]
            continue
        if not line.strip():
            active_section = None
            continue
        if active_section != section:
            continue

        parts = line.split()
        if len(parts) < 2 or not all(ch in "0123456789abcdefABCDEF" for ch in parts[0]):
            continue
        offset = int(parts[0], 16)
        for byte_offset in range(offset, offset + relocation_width(parts[1])):
            covered.add(byte_offset)
    return covered


def mismatched_payload_sections(diff: dict) -> list[str]:
    names: list[str] = []
    for section in diff.get("left", {}).get("sections", []):
        if section.get("kind") not in {"SECTION_CODE", "SECTION_DATA", "SECTION_RODATA"}:
            continue
        match = section.get("match_percent")
        if match is not None and float(match) < 100.0:
            names.append(section["name"])
    return names


def section_diff_is_relocation_or_padding_only(
    src: bytes, target: bytes, reloc_bytes: set[int]
) -> bool:
    shared_size = min(len(src), len(target))
    for index in range(shared_size):
        if src[index] != target[index] and index not in reloc_bytes:
            return False

    if len(src) == len(target):
        return True
    if len(src) < len(target):
        return all(byte == 0 for byte in target[shared_size:])
    return all(byte == 0 for byte in src[shared_size:])


def is_relocation_or_padding_only_mismatch(src_obj: Path, target_obj: Path, diff: dict) -> bool:
    sections = mismatched_payload_sections(diff)
    if not sections:
        return False

    with tempfile.TemporaryDirectory(prefix="sdk-audit-", dir=REPO_ROOT / "temp") as tmp:
        work_dir = Path(tmp)
        for section in sections:
            src = section_bytes(src_obj, section, work_dir)
            target = section_bytes(target_obj, section, work_dir)
            if src is None or target is None or len(src) != len(target):
                if src is None or target is None:
                    return False

            reloc_bytes = source_relocation_bytes(src_obj, section)
            if not reloc_bytes and len(src) == len(target):
                return False

            if not section_diff_is_relocation_or_padding_only(src, target, reloc_bytes):
                return False
    return True


def is_dead_stripped_text_prefix_mismatch(src_obj: Path, target_obj: Path, diff: dict) -> bool:
    sections = mismatched_payload_sections(diff)
    if ".text" not in sections:
        return False

    with tempfile.TemporaryDirectory(prefix="sdk-audit-", dir=REPO_ROOT / "temp") as tmp:
        work_dir = Path(tmp)
        for section in sections:
            src = section_bytes(src_obj, section, work_dir)
            target = section_bytes(target_obj, section, work_dir)
            if src is None or target is None:
                return False

            if section == ".text":
                if len(src) <= len(target):
                    return False
                if src[-len(target) :] != target:
                    return False
                continue

            reloc_bytes = source_relocation_bytes(src_obj, section)
            if len(src) == len(target) and not reloc_bytes:
                return False
            if not section_diff_is_relocation_or_padding_only(src, target, reloc_bytes):
                return False
    return True


def audit_object(version: str, obj: ConfigObject) -> AuditResult:
    src_obj = object_path(version, "src", obj.path)
    target_obj = object_path(version, "obj", obj.path)
    if not src_obj.exists():
        return AuditResult(obj, None, None, 0, 0, f"missing source object: {src_obj}")
    if not target_obj.exists():
        return AuditResult(obj, None, None, 0, 0, f"missing target object: {target_obj}")

    cmd = [
        str(REPO_ROOT / "tools" / "objdiff-cli.exe"),
        "diff",
        "-1",
        str(src_obj),
        "-2",
        str(target_obj),
        "-o",
        "-",
        "--format",
        "json",
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        return AuditResult(obj, None, None, 0, 0, proc.stderr.strip() or proc.stdout.strip())

    diff = json.loads(proc.stdout)
    if not has_target_payload(diff):
        return AuditResult(obj, None, None, text_size(diff), 0, skipped="empty target split")
    if is_dead_stripped_text_prefix_mismatch(src_obj, target_obj, diff):
        return AuditResult(obj, None, None, text_size(diff), 0, skipped="dead-stripped text prefix")
    if is_relocation_or_padding_only_mismatch(src_obj, target_obj, diff):
        return AuditResult(obj, None, None, text_size(diff), 0, skipped="relocation/padding-only extracted target split")

    return AuditResult(
        obj=obj,
        code_percent=section_min(diff, {"SECTION_CODE"}),
        data_percent=section_min(diff, {"SECTION_DATA", "SECTION_RODATA", "SECTION_BSS"}),
        text_size=text_size(diff),
        bad_symbols=bad_symbol_count(diff),
    )


def fmt_percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:6.2f}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit SDK objects marked Matching/MatchingFor against extracted target objects."
    )
    parser.add_argument("-v", "--version", default="GSAE01", help="Target version (default: GSAE01)")
    parser.add_argument("--all-configured", action="store_true", help="Also audit matching SDK objects absent from config.json")
    parser.add_argument("--fail-on-mismatch", action="store_true", help="Exit nonzero if any audited object is not exact")
    parser.add_argument("--show-skipped", action="store_true", help="Print SDK objects skipped by reason")
    parser.add_argument("--limit", type=int, default=0, help="Maximum mismatches to print (default: all)")
    args = parser.parse_args()

    objects = matching_sdk_objects(REPO_ROOT / "configure.py")
    active = active_unit_names(args.version)
    if not args.all_configured:
        objects = [obj for obj in objects if obj.path in active]

    mismatches: list[AuditResult] = []
    skipped: list[AuditResult] = []
    for obj in objects:
        result = audit_object(args.version, obj)
        if result.skipped:
            skipped.append(result)
            continue
        if not result.ok:
            mismatches.append(result)

    print(f"audited={len(objects)} mismatches={len(mismatches)} skipped={len(skipped)} version={args.version}")
    for result in mismatches[: args.limit or None]:
        if result.error:
            print(f"error path={result.obj.path} detail={result.error}")
        else:
            print(
                f"code={fmt_percent(result.code_percent)} "
                f"data={fmt_percent(result.data_percent)} "
                f"text=0x{result.text_size:X} "
                f"bad-symbols={result.bad_symbols:2d} "
                f"path={result.obj.path}"
            )
    if args.show_skipped:
        for result in skipped:
            print(f"skip path={result.obj.path} reason={result.skipped} text=0x{result.text_size:X}")

    return 1 if args.fail_on_mismatch and mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
