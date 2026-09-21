"""Export a verified GC/1.3 capture for the sibling MWCC scan-order solver.

    python3 tools/mwcc_register_order_input.py CAPTURE/trace.json \
        --function cMenuSetItems --movable 34:60 --output order-input.json
    python3 ../mwcc/tools/solve_gc13_register_order.py \
        --input order-input.json --output order-result.json

Ranges are half-open. Movable IDs are hypotheses about source-controlled birth
order, not proven declaration mappings. The export fixes the interference graph
and full projected color vector; it does not claim source feasibility. Compiler
object names, when available, remain in the adjacent original capture.
"""

import argparse
import hashlib
import json
from pathlib import Path

import strucdiff
from mwcc_register_compare import load_capture
from mwcc_retail_registers import project, registers
from tricky_backend_graph import replay_simplification


def movable_registers(values, count):
    result = []
    for value in values:
        if ":" in value:
            start, stop = map(int, value.split(":"))
            if stop <= start:
                raise ValueError("empty or reversed movable range")
            result.extend(range(start, stop))
        else:
            result.append(int(value))
    if len(set(result)) != len(result):
        raise ValueError("duplicate movable register")
    if not result or any(register < 32 or register >= count for register in result):
        raise ValueError("movable register outside virtual graph")
    return sorted(result)


def export(path, function, movable):
    document = json.loads(path.read_text())
    capture = load_capture(path, function)
    if capture["class"] != 4:
        raise ValueError("scan-order export currently supports GPR captures only")
    before = next(snapshot for snapshot in document["snapshots"]
                  if snapshot["name"] == function and snapshot["stage"] == "BEFORE GPR SIMPLIFICATION")
    policy = before["simplification_policy"]
    removals = replay_simplification(capture["graph"], capture["colored"],
                                    policy["available"], policy["temporary_cutoff"])
    if removals:
        raise ValueError("scan-order solver does not model high-degree removals")
    target, _ = strucdiff.obj_paths(document["unit"])
    projection = project(capture, strucdiff.text_lines(str(path.parent / "traced.o"), function),
                         strucdiff.text_lines(target, function))
    if not projection["retail_projection_valid_with_unmapped_colors_unchanged"]:
        raise ValueError("retail color projection is unresolved or conflicts with interference")
    graph = capture["graph"]
    colors = [node["prefix"][6] for node in capture["colored"]]
    desired = colors.copy()
    weights = [0] * len(graph)
    for change in projection["changes"]:
        desired[change["virtual"]] = change["retail"]
    skipped = set(projection["skipped_instruction_indices"])
    for index, instruction in enumerate(capture["final"]):
        if index not in skipped:
            for register in registers(capture["records"][instruction["address"]]):
                weights[register] += 1
    return {
        "schema": "gc13-register-order-search-v1", "compiler_sha256": document["compiler_sha256"],
        "function": function, "trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "nodes": [{"neighbors": node["neighbors"], "degree": node["prefix"][5],
                   "color": node["prefix"][6], "excluded": bool(node["prefix"][7] & 4)} for node in graph],
        "policy": before["color_policy"], "threshold": len(policy["available"]),
        "weights": weights, "desired_colors": desired, "baseline_colors": colors,
        "movable_registers": movable_registers(movable, len(graph)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--movable", nargs="+", required=True, metavar="ID_OR_START:STOP")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = export(args.capture, args.function, args.movable)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Exported {len(result['nodes'])} nodes; {len(result['movable_registers'])} movable identities")


if __name__ == "__main__":
    main()
