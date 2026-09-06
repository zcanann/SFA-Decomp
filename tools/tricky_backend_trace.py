"""Trace Tricky's residual instructions through GC/1.3's optimizer on Windows.

The capture is diagnostic only: a private compiler process's disabled dump hook
is intercepted, and its complete output object must equal an ordinary compile.
No compiler file, game source, or production build flags are modified.

    python tools/tricky_backend_trace.py --function trickyDigTunnel --instruction 330
    python tools/tricky_backend_trace.py --read build/flag_probe/tricky_backend/trace.json

IR addresses identify observed arena records, not proven source-variable lineage.
This diagnoses the reconstructed source; it does not establish retail provenance.
Some dump sites run only when a pass changes IR; absent dumps do not mean absent passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import flag_probe
import strucdiff
from compiler_command import split_command_line
from tricky_backend_ir import COMPILER_SHA256, describe, instruction_history, validate_alignment, validate_snapshot
from tricky_object_compare import read_object
from tricky_source_order_probe import compile_command


ROOT = Path(__file__).resolve().parents[1]
UNIT = "main/dlls/objects/196_Tricky/tricky"
SOURCE = ROOT / "src/dlls/objects/196_Tricky/tricky.c"
FUNCTIONS = ("trickyDigTunnel", "trickyUpdateMovementState")
OUTPUT = ROOT / "build/flag_probe/tricky_backend"


def inspect(snapshots, obj, functions):
    result = {}
    object_snapshot = read_object(obj)
    for name in functions:
        stages = [s for s in snapshots if s["name"] == name]
        if not stages or stages[-1]["stage"] != "FINAL CODE":
            raise ValueError(f"missing final stage for {name}")
        for stage in stages:
            validate_snapshot(stage)
        assembly = strucdiff.text_lines(str(obj), name)
        code = object_snapshot.functions[name]
        instructions = validate_alignment(stages[-1], assembly, code)
        rows, retail, current, _, _ = strucdiff.analyse(UNIT, name, str(obj))
        differences = []
        for marker, target_index, current_index in rows:
            if marker == " ":
                continue
            differences.append({
                "kind": marker, "retail_index": target_index, "current_index": current_index,
                "retail": retail[target_index] if target_index is not None else None,
                "current": current[current_index] if current_index is not None else None,
                "history": instruction_history(stages, instructions[current_index]) if current_index is not None else [],
            })
        result[name] = {"stages": len(stages), "instructions": instructions, "differences": differences}
    return result


def run_capture(source, directory, functions):
    from tricky_backend_capture_win import capture

    directory.mkdir(parents=True, exist_ok=True)
    base = split_command_line(flag_probe.base_cmd(UNIT))
    # Fresh directories prevent stale objects from satisfying the equivalence gate.
    with tempfile.TemporaryDirectory(prefix="capture-", dir=directory) as scratch:
        scratch = Path(scratch)
        normal, traced = scratch / "normal", scratch / "traced"
        normal.mkdir()
        traced.mkdir()
        command = compile_command(base, source, normal)
        subprocess.run(command, cwd=ROOT, check=True, timeout=30, capture_output=True)
        normal_obj = normal / (source.stem + ".o")
        command = compile_command(base, source, traced)
        compiler_index = next(i for i, value in enumerate(command) if Path(value).name.lower() == "mwcceppc.exe")
        compiler = (ROOT / command[compiler_index]).resolve()
        snapshots, log = capture(command[compiler_index:] + ["-pragma", "debug_listing on"], ROOT, set(functions))
        traced_obj = traced / (source.stem + ".o")
        normal_hash, traced_hash = read_object(normal_obj).digest, read_object(traced_obj).digest
        if normal_hash != traced_hash:
            raise ValueError(f"instrumentation changed the output object: {normal_hash} != {traced_hash}")
        report = inspect(snapshots, traced_obj, functions)
        document = {
            "schema": 1, "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
            "object_sha256": traced_hash, "source": str(source),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "command": command[compiler_index:], "snapshots": snapshots,
        }
        shutil.copyfile(traced_obj, directory / "traced.o")
        (directory / "compiler.log").write_text(log, encoding="utf-8")
        (directory / "trace.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
        (directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return document, report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--function", choices=FUNCTIONS, action="append")
    parser.add_argument("--instruction", type=int, action="append", help="Current ELF instruction index; repeat to inspect")
    parser.add_argument("--read", type=Path, help="Inspect a previous trace and its adjacent traced.o without compiling")
    args = parser.parse_args()
    if args.instruction and len(args.function or []) != 1:
        parser.error("--instruction requires exactly one --function")
    if args.read:
        document = json.loads(args.read.read_text(encoding="utf-8"))
        if document["schema"] != 1:
            raise ValueError("unsupported trace schema")
        if document["compiler_sha256"] != COMPILER_SHA256:
            raise ValueError("trace compiler does not match the decoder profile")
        obj = args.read.parent / "traced.o"
        if read_object(obj).digest != document["object_sha256"]:
            raise ValueError("trace object hash does not match captured provenance")
        functions = args.function or sorted({s["name"] for s in document["snapshots"]})
        report = inspect(document["snapshots"], obj, functions)
    else:
        if sys.platform != "win32":
            parser.error("capture requires Windows; --read works without the Windows debugger")
        document, report = run_capture(args.source.resolve(), args.output.resolve(), args.function or FUNCTIONS)
    print("Instrumented/ordinary raw object SHA256:", document["object_sha256"])
    for name, item in report.items():
        print(f"{name}: {len(item['instructions'])} aligned instructions; {item['stages']} captured stages; {len(item['differences'])} retail differences")
        for difference in item["differences"]:
            print(f"  {difference['current_index']}: {difference['retail']} | {difference['current']}")
        for index in args.instruction or []:
            if not 0 <= index < len(item["instructions"]):
                parser.error(f"instruction index out of range: {index}")
            final = item["instructions"][index]
            print(f"Instruction {index}, block {final['block_id']} (address lineage is provisional):")
            stages = [s for s in document["snapshots"] if s["name"] == name]
            previous = None
            for row in instruction_history(stages, final):
                description = describe(row["record"])
                if description != previous:
                    print(f"  [{row['stage_index']}] {row['stage']}: {description}")
                previous = description


if __name__ == "__main__":
    main()
