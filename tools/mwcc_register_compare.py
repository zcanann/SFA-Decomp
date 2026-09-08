"""Compare virtual-register roles in two verified GC/1.3 backend captures.

Aligns equal opcode streams by emitted instruction position, then follows each
record back to the pre-rewrite snapshot. This distinguishes changed register
partitioning from changed numbering/coloring. It is not a semantic equivalence
check and does not modify either compiler or source.
"""

import argparse
import hashlib
import json
from pathlib import Path

from tricky_backend_graph import register_kind
from tricky_backend_ir import COMPILER_SHA256, decode, emitted_instructions
from tricky_backend_trace import inspect


def load_capture(path, function):
    document = json.loads(path.read_text())
    if document.get("schema") != 1 or document.get("compiler_sha256") != COMPILER_SHA256:
        raise ValueError("unsupported capture schema or compiler")
    obj = path.parent / "traced.o"
    if hashlib.sha256(obj.read_bytes()).hexdigest() != document["object_sha256"]:
        raise ValueError("captured object hash mismatch")
    register_class = document["register_class"]
    # Reuse the complete IR/object alignment and allocator replay checks.
    inspect(document["snapshots"], obj, [function], require_graph=True,
            unit=document["unit"], required_register_class=register_class)
    stages = [s for s in document["snapshots"] if s["name"] == function]
    kind, _ = register_kind(register_class)
    before = next(s for s in stages if s["stage"] == f"BEFORE {kind} SIMPLIFICATION")
    rewrite = next(s for s in stages if s["stage"] == f"BEFORE {kind} REWRITE")
    records = {i["address"]: decode(i) for b in rewrite["blocks"] for i in b["instructions"]}
    return {"class": register_class, "final": emitted_instructions(stages[-1]),
            "records": records, "graph": before["coloring_graph"],
            "colored": rewrite["coloring_graph"], "object_sha256": document["object_sha256"]}


def match_roles(left, right):
    if left["class"] != right["class"]:
        raise ValueError("captures use different register classes")
    if len(left["final"]) != len(right["final"]):
        raise ValueError("emitted instruction counts differ")
    forward, reverse, positions = {}, {}, {}
    skipped = []
    for index, (a, b) in enumerate(zip(left["final"], right["final"])):
        if a["opcode"] != b["opcode"] or len(a["operands"]) != len(b["operands"]):
            raise ValueError(f"instruction shape differs at index {index}")
        ar, br = left["records"].get(a["address"]), right["records"].get(b["address"])
        if ar is None or br is None:
            skipped.append(index)  # Prologue/epilogue records can be created after allocation.
            continue
        if ar["opcode"] != br["opcode"] or len(ar["operands"]) != len(br["operands"]):
            raise ValueError(f"pre-rewrite instruction shape differs at index {index}")
        for ao, bo in zip(ar["operands"], br["operands"]):
            selected_a = ao["kind"] == 0 and ao["register_class"] == left["class"]
            selected_b = bo["kind"] == 0 and bo["register_class"] == right["class"]
            if selected_a != selected_b:
                raise ValueError(f"operand class differs at index {index}")
            if not selected_a:
                continue
            av, bv = ao["number"], bo["number"]
            forward.setdefault(av, set()).add(bv)
            reverse.setdefault(bv, set()).add(av)
            positions.setdefault((av, bv), set()).add(index)
    conflicts = {"left": {str(k): sorted(v) for k, v in forward.items() if len(v) != 1},
                 "right": {str(k): sorted(v) for k, v in reverse.items() if len(v) != 1}}
    mapping = {a: next(iter(bs)) for a, bs in forward.items()
               if len(bs) == 1 and len(reverse[next(iter(bs))]) == 1}
    changes = []
    for av, bv in sorted(mapping.items()):
        ac = left["colored"][av]["prefix"][6]
        bc = right["colored"][bv]["prefix"][6]
        if ac != bc:
            changes.append({"left_virtual": av, "right_virtual": bv,
                            "left_physical": ac, "right_physical": bc,
                            "instruction_indices": sorted(positions[av, bv])})
    # Fixed registers may have edges without occurring explicitly in the code.
    fixed = {i: i for i in range(32)}
    for av, bv in mapping.items():
        if (av < 32 or bv < 32) and av != bv:
            raise ValueError("correspondence changes a fixed register")
    mapping = {**fixed, **mapping}
    mismatches, unseen = [], set()
    for av, bv in sorted(mapping.items()):
        an = left["graph"][av]["neighbors"]
        bn = right["graph"][bv]["neighbors"]
        projected = {mapping[n] for n in an if n in mapping}
        observed = set(bn) & set(mapping.values())
        if projected != observed:
            mismatches.append({"left_virtual": av, "right_virtual": bv,
                               "left_only_neighbors_in_right_ids": sorted(projected - observed),
                               "right_only_neighbors": sorted(observed - projected)})
        unseen.update(("left", n) for n in an if n not in mapping)
        unseen.update(("right", n) for n in bn if n not in mapping.values())
    return {"instruction_count": len(left["final"]), "skipped_instruction_indices": skipped,
            "register_partition_conflicts": conflicts, "mapped_registers_including_fixed": len(mapping),
            "mapped_graph_edge_differences": mismatches,
            "unmapped_graph_neighbors": sorted(unseen), "physical_changes": changes,
            "object_sha256": [left["object_sha256"], right["object_sha256"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    left, right = (load_capture(path, args.function) for path in (args.left, args.right))
    result = match_roles(left, right)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    _, prefix = register_kind(left["class"])
    print(f"{result['instruction_count']} aligned instructions; "
          f"{result['mapped_registers_including_fixed']} mapped registers including fixed registers")
    print("Partition conflicts:", sum(len(v) for v in result["register_partition_conflicts"].values()))
    print("Mapped graph edge differences:", len(result["mapped_graph_edge_differences"]))
    print("Unmapped graph neighbors:", len(result["unmapped_graph_neighbors"]))
    for change in result["physical_changes"]:
        print(f"v{change['left_virtual']} -> v{change['right_virtual']}: "
              f"{prefix}{change['left_physical']} -> {prefix}{change['right_physical']}; "
              f"instructions {change['instruction_indices']}")


if __name__ == "__main__":
    main()
