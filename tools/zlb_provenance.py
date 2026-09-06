#!/usr/bin/env python3
"""Audit zlb's retail fingerprints and optionally compare installed compilers.

Writes experiments under build/ without changing source or the project config.
The default audit is offline; --fetch-gcc explicitly downloads upstream backend
sources. --compile requires a generated build/GSAE01/obj/main/zlb.o.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import urllib.request

from orig.dol_vtables import DolFile


ROOT = Path(__file__).resolve().parents[1]
PRODG_VERSIONS = ("3.5", "3.5b140", "3.7", "3.8.1", "3.9.3")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command: list[str | Path]) -> str:
    result = subprocess.run(
        [str(arg) for arg in command], cwd=ROOT, capture_output=True,
        text=True, errors="replace", timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def retail_audit(dol_path: Path) -> dict:
    dol = DolFile(dol_path)
    mcrxr = []
    frames = []
    for section in dol.text_sections:
        for offset in range(0, section.size, 4):
            word = struct.unpack_from(">I", dol.data, section.offset + offset)[0]
            address = f"0x{section.address + offset:08X}"
            # Ignore the destination CR field, but require every other opcode bit.
            if word & 0xFC7FFFFF == 0x7C000400:
                mcrxr.append(address)
            # stwu r1,negative-displacement(r1).
            if word >> 16 == 0x9421 and word & 0x8000:
                size = 0x10000 - (word & 0xFFFF)
                if size % 8:
                    frames.append({"address": address, "size": size})
    return {"path": str(dol_path), "sha256": sha256(dol.data),
            "mcrxr": mcrxr, "stack_allocations_not_multiple_of_8": frames}


def compiler_inventory() -> list[dict]:
    result = []
    for version in PRODG_VERSIONS:
        path = ROOT / "build/compilers/ProDG" / version / "cc1.exe"
        if not path.is_file():
            result.append({"version": version, "missing": True})
            continue
        data = path.read_bytes()
        result.append({"version": version, "sha256": sha256(data),
                       "mcrxr_string_occurrences": data.count(b"mcrxr")})
    return result


def fetch_backends(output: Path) -> list[dict]:
    output.mkdir(parents=True, exist_ok=True)
    result = []

    def record(version: str, suffix: str, data: bytes, url: str) -> None:
        path = output / f"gcc-{version}-rs6000.{suffix}"
        path.write_bytes(data)
        result.append({"version": version, "file": str(path), "url": url,
                       "sha256": sha256(data), "mcrxr_occurrences": data.count(b"mcrxr")})

    url = "https://ftp.gnu.org/gnu/gcc/gcc-2.7.2.3.tar.gz"
    with urllib.request.urlopen(url, timeout=30) as response:
        archive = response.read()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for suffix in ("c", "md"):
            member = tar.extractfile(f"gcc-2.7.2.3/config/rs6000/rs6000.{suffix}")
            if member is None:
                raise RuntimeError(f"Missing rs6000.{suffix} in {url}")
            record("2.7.2.3", suffix, member.read(), url)
    for version in ("2.8.1", "2.95.2", "3.0"):
        for suffix in ("c", "md"):
            url = (f"https://raw.githubusercontent.com/gcc-mirror/gcc/releases/gcc-{version}"
                   f"/gcc/config/rs6000/rs6000.{suffix}")
            with urllib.request.urlopen(url, timeout=30) as response:
                record(version, suffix, response.read(), url)
    return result


def object_fingerprint(path: Path, output: Path) -> dict:
    asm = run([ROOT / "build/binutils/powerpc-eabi-objdump", "-dr", path])
    output.write_text(asm)
    body = asm.split("<zlbDecompress>:", 1)[1]
    body = re.split(r"\n(?:Disassembly of section|[0-9a-f]+ <)", body)[0]
    instructions = re.findall(
        r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(\S+)[ \t]*(.*)", body, re.M,
    )
    if not instructions:
        raise RuntimeError(f"No instructions parsed from {path}")
    frame = None
    for opcode, operands in instructions:
        if opcode == "stwu" and (match := re.fullmatch(r"r1,-(\d+)\(r1\)", operands)):
            frame = int(match[1])
            break
    return {
        "instructions": len(instructions), "stwu_frame": frame,
        "mcrxr": sum(op == "mcrxr" for op, _ in instructions),
        "addme": sum(op.startswith("addme") for op, _ in instructions),
        "andi_dot": sum(op == "andi." for op, _ in instructions),
        "prologue": [f"{op} {args}".rstrip() for op, args in instructions[:6]],
    }


def compile_probes(source: Path, output: Path) -> list[dict]:
    target = ROOT / "build/GSAE01/obj/main/zlb.o"
    if not target.is_file():
        raise RuntimeError("Generate the matching build first: missing " + str(target))
    output.mkdir(parents=True, exist_ok=True)
    wrapper = [] if os.name == "nt" else [ROOT / "build/tools/wibo"]
    prodg_flags = ["-quiet", "-O1", "-fno-common", "-frerun-loop-opt", "-frerun-cse-after-loop"]
    profiles = [
        (f"prodg-{v}", ROOT / f"build/compilers/ProDG/{v}/cc1.exe", prodg_flags)
        for v in PRODG_VERSIONS
    ]
    cc = profiles[0][1]
    profiles.extend([
        ("prodg-3.5-no-update", cc, prodg_flags + ["-mno-update"]),
        ("prodg-3.5-O0", cc, ["-quiet", "-O0", "-fno-common"]),
        ("prodg-3.5-O2", cc, ["-quiet", "-O2", "-fno-common"]),
    ])
    mwcc_flags = ["-nodefaults", "-proc", "gekko", "-align", "powerpc", "-enum", "int",
                  "-fp", "hardware", "-Cpp_exceptions", "off", "-inline", "off",
                  "-RTTI", "off", "-i", "include", "-lang", "c"]
    for level in (0, 1, 4):
        profiles.append((f"mwcc-1.3-O{level}", ROOT / "build/compilers/GC/1.3/mwcceppc.exe",
                         mwcc_flags + [f"-O{level}"]))
    results = []
    units = []
    for name, compiler, flags in profiles:
        directory = output / name
        directory.mkdir(exist_ok=True)
        local_source = directory / "zlb.c"
        local_source.write_bytes(source.read_bytes())
        obj = directory / "zlb.o"
        obj.unlink(missing_ok=True)
        record = {"name": name, "compiler": str(compiler), "flags": flags}
        try:
            record["compiler_sha256"] = sha256(compiler.read_bytes())
            if name.startswith("prodg"):
                run([*wrapper, compiler.parent / "cpp.exe", "-Iinclude", "-P",
                     local_source, directory / "zlb.i"])
                run([*wrapper, compiler, directory / "zlb.i", *flags,
                     "-o", directory / "zlb.s"])
                run([ROOT / "build/binutils/powerpc-eabi-as", "-mgekko",
                     directory / "zlb.s", "-o", obj])
            else:
                run([*wrapper, compiler, *flags, "-c", local_source, "-o", obj])
            record.update(object_fingerprint(obj, directory / "zlb.dump"))
            record["object_sha256"] = sha256(obj.read_bytes())
            units.append({"name": name, "target_path": str(target), "base_path": str(obj)})
        except (OSError, RuntimeError, IndexError, subprocess.TimeoutExpired) as error:
            record["error"] = str(error)
        results.append(record)
    (output / "objdiff.json").write_text(json.dumps({
        "min_version": "2.0.0-beta.5", "build_target": False, "units": units,
    }))
    run([ROOT / "build/tools/objdiff-cli", "report", "generate", "-p", output,
         "-o", output / "report.json"])
    report = json.loads((output / "report.json").read_text())
    for unit in report["units"]:
        record = next(row for row in results if row["name"] == unit["name"])
        function = next(fn for fn in unit["functions"] if fn["name"] == "zlbDecompress")
        record["match_percent"] = function.get("fuzzy_match_percent", 0)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile", action="store_true", help="compile the installed-toolchain matrix")
    parser.add_argument("--fetch-gcc", action="store_true", help="download and audit upstream GCC backends")
    parser.add_argument("--source", type=Path, default=ROOT / "src/main/zlb.c")
    parser.add_argument("--output", type=Path, default=ROOT / "build/zlb-provenance")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = {"retail": retail_audit(ROOT / "orig/GSAE01/sys/main.dol"),
              "source_sha256": sha256(args.source.read_bytes()), "prodg": compiler_inventory()}
    target = ROOT / "build/GSAE01/obj/main/zlb.o"
    if target.is_file():
        result["target"] = object_fingerprint(target, output / "retail.dump")
    if args.fetch_gcc:
        result["gcc_backends"] = fetch_backends(output / "backends")
    if args.compile:
        result["probes"] = compile_probes(args.source.resolve(), output / "probes")
    (output / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["retail"], indent=2))
    for probe in result.get("probes", []):
        print(probe["name"], {key: probe.get(key) for key in
              ("instructions", "stwu_frame", "mcrxr", "andi_dot", "match_percent", "error")})
    print(f"Full audit: {output / 'audit.json'}")


if __name__ == "__main__":
    main()
