"""Trace Tricky's residual instructions through GC/1.3's optimizer on Windows.

The capture is diagnostic only: a private compiler process's disabled dump hook
is intercepted, and its complete output object must equal an ordinary compile.
No compiler file, game source, or production build flags are modified.

    python tools/tricky_backend_trace.py --function trickyDigTunnel --instruction 330
    python tools/tricky_backend_trace.py --graph --function trickyUpdateMovementState --register 74 --register 76
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
from tricky_backend_ir import (
    COMPILER_SHA256, describe, immediate_commoning, instruction_history, validate_alignment, validate_snapshot,
)
from tricky_backend_graph import coloring_order, describe_node, replay_simplification, validate_graph, validate_rewrite
from tricky_object_compare import read_object
from tricky_source_order_probe import compile_command


ROOT = Path(__file__).resolve().parents[1]
UNIT = "main/dlls/objects/196_Tricky/tricky"
SOURCE = ROOT / "src/dlls/objects/196_Tricky/tricky.c"
FUNCTIONS = ("trickyDigTunnel", "trickyUpdateMovementState")
OUTPUT = ROOT / "build/flag_probe/tricky_backend"


def inspect(snapshots, obj, functions, require_graph=False):
    result = {}
    object_snapshot = read_object(obj)
    for name in functions:
        stages = [s for s in snapshots if s["name"] == name]
        if not stages or stages[-1]["stage"] != "FINAL CODE":
            raise ValueError(f"missing final stage for {name}")
        graphs = [stage for stage in stages if "coloring_graph" in stage]
        if require_graph and not ({stage.get("graph_colored", True) for stage in graphs} == {False, True}):
            raise ValueError(f"missing GPR graph for {name}: both initial and colored graphs are required")
        paired_graphs = require_graph or any(not stage.get("graph_colored", True) for stage in graphs)
        initial_graph = None
        choices = []
        for stage in stages:
            validate_snapshot(stage)
            if "coloring_graph" in stage:
                colored = stage.get("graph_colored", True)
                validate_graph(stage["coloring_graph"], colored=colored)
                if colored:
                    if paired_graphs and initial_graph is None:
                        raise ValueError(f"colored GPR graph without a preceding initial graph for {name}")
                    coloring_order(stage["coloring_graph"])
                    validate_rewrite(stage, stages[-1])
                    if initial_graph is not None:
                        choices = replay_simplification(initial_graph["coloring_graph"], stage["coloring_graph"],
                                                        initial_graph["available_gprs"], initial_graph["original_gpr_count"])
                        initial_graph = None
                else:
                    if initial_graph is not None:
                        raise ValueError(f"unpaired initial GPR graph for {name}")
                    initial_graph = stage
        if initial_graph is not None:
            raise ValueError(f"unpaired initial GPR graph for {name}")
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
        result[name] = {"stages": len(stages), "instructions": instructions, "differences": differences,
                        "high_degree_removals": choices}
    return result


def run_capture(source, directory, functions, graph=False):
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
        snapshots, log = capture(command[compiler_index:] + ["-pragma", "debug_listing on"], ROOT, set(functions), graph=graph)
        traced_obj = traced / (source.stem + ".o")
        normal_hash, traced_hash = read_object(normal_obj).digest, read_object(traced_obj).digest
        if normal_hash != traced_hash:
            raise ValueError(f"instrumentation changed the output object: {normal_hash} != {traced_hash}")
        report = inspect(snapshots, traced_obj, functions, require_graph=graph)
        document = {
            "schema": 1, "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
            "object_sha256": traced_hash, "source": str(source),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "command": command[compiler_index:] + ["-pragma", "debug_listing on"],
            "graph_requested": graph, "snapshots": snapshots,
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
    parser.add_argument("--graph", action="store_true", help="Capture and replay the live GPR simplification graph")
    parser.add_argument("--register", type=int, action="append", help="Virtual GPR graph index; requires --graph when capturing")
    parser.add_argument("--read", type=Path, help="Inspect a previous trace and its adjacent traced.o without compiling")
    args = parser.parse_args()
    if args.instruction and len(args.function or []) != 1:
        parser.error("--instruction requires exactly one --function")
    if args.register and (len(args.function or []) != 1 or not (args.graph or args.read)):
        parser.error("--register requires one --function and either --graph or --read")
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
        report = inspect(document["snapshots"], obj, functions, require_graph=args.graph)
    else:
        if sys.platform != "win32":
            parser.error("capture requires Windows; --read works without the Windows debugger")
        document, report = run_capture(args.source.resolve(), args.output.resolve(), args.function or FUNCTIONS, args.graph)
    print("Instrumented/ordinary raw object SHA256:", document["object_sha256"])
    for name, item in report.items():
        print(f"{name}: {len(item['instructions'])} aligned instructions; {item['stages']} captured stages; {len(item['differences'])} retail differences")
        for difference in item["differences"]:
            print(f"  {difference['current_index']}: {difference['retail']} | {difference['current']}")
        graphs = [s for s in document["snapshots"] if s["name"] == name and "coloring_graph" in s]
        if args.register and not graphs:
            parser.error("this trace has no coloring graph")
        for snapshot in graphs:
            graph = snapshot["coloring_graph"]
            colored = snapshot.get("graph_colored", True)
            order = coloring_order(graph) if colored else []
            print(f"  {snapshot['stage']}: {len(graph)} nodes; coloring prefix {order[:8]}")
            for register in args.register or []:
                print("  " + describe_node(graph, register, colored=colored))
        if item["high_degree_removals"]:
            print("  Replayed high-degree removals:", item["high_degree_removals"])
        for index in args.instruction or []:
            if not 0 <= index < len(item["instructions"]):
                parser.error(f"instruction index out of range: {index}")
            final = item["instructions"][index]
            print(f"Instruction {index}, block {final['block_id']} (address lineage is provisional):")
            stages = [s for s in document["snapshots"] if s["name"] == name]
            previous = None
            colored = False
            for row in instruction_history(stages, final):
                colored |= row["stage"] == "AFTER REGISTER COLORING"
                description = describe(row["record"])
                bounds = stages[row["stage_index"]].get("immediate_commoning")
                eligible = immediate_commoning(row["record"], bounds) if bounds and not colored else None
                if eligible is not None:
                    description += (f"; late-VN range [{bounds['first_register']}, {bounds['last_register']}] "
                                    + ("includes" if eligible else "excludes") + " destination")
                if description != previous:
                    print(f"  [{row['stage_index']}] {row['stage']}: {description}")
                previous = description


if __name__ == "__main__":
    main()
