"""Project retail GPR operands onto a verified GC/1.3 backend capture.

This diagnoses register allocation, not object equality. Instruction order and
mnemonics must agree; immediates, branches, data and relocation targets remain
separate matching checks. Commutative source operands are constrained together
instead of falsely reporting a register split when an ADD reverses its inputs.

    python3 tools/mwcc_retail_registers.py build/flag_probe/engine0_map_staging/trace.json \
        --function mapScreenDrawHud
"""

import argparse
import json
from pathlib import Path
import re

from mwcc_register_compare import load_capture
import strucdiff


COMMUTATIVE = {"add", "mullw", "and", "or", "xor"}


def registers(instruction):
    return [operand["number"] for operand in instruction["operands"]
            if operand["kind"] == 0 and operand["register_class"] == 4]


def project(capture, source_assembly, target_assembly):
    final = capture["final"]
    if capture["class"] != 4:
        raise ValueError("retail projection currently requires a GPR capture")
    if len(final) != len(source_assembly) or len(final) != len(target_assembly):
        raise ValueError("instruction counts differ; resolve structural differences first")

    constraints, positions, skipped = [], {}, []
    domains = {}
    for index, (instruction, source, target) in enumerate(zip(final, source_assembly, target_assembly)):
        mnemonic = source.split()[0]
        if mnemonic != target.split()[0]:
            raise ValueError(f"instruction mnemonic differs at index {index}")
        record = capture["records"].get(instruction["address"])
        if instruction["opcode"] in (0x01, 0x13) or record is None:
            skipped.append(index)  # Calls have implicit clobbers; late prologues lack virtual operands.
            continue
        if record["opcode"] != instruction["opcode"]:
            raise ValueError(f"pre-rewrite opcode differs at index {index}")
        virtual = registers(record)
        target_text = target.split("<", 1)[0]
        physical = [int(number) for number in re.findall(r"\br(\d+)\b", target_text)]
        if "(0)" in target_text:
            physical.append(0)  # Objdump spells a D-form zero base as (0).
        if len(virtual) != len(physical):
            raise ValueError(f"register operand count differs at index {index}")
        alternatives = [physical]
        if mnemonic in COMMUTATIVE and len(physical) == 3:
            alternatives.append([physical[0], physical[2], physical[1]])
        choices = []
        for alternative in alternatives:
            choice = {}
            for register, color in zip(virtual, alternative):
                if register in choice and choice[register] != color:
                    break
                choice[register] = color
            else:
                if choice not in choices:
                    choices.append(choice)
        constraints.append((index, choices))
        for register in virtual:
            domains.setdefault(register, set(range(32)))
            positions.setdefault(register, set()).add(index)

    # Fixed physical aliases contribute separately to the compiler's degree
    # counters, but must retain their captured physical colors.
    for register in domains:
        fixed = capture["graph"][register]["prefix"][6]
        if fixed >= 0:
            domains[register] = {fixed}

    changed = True
    while changed:
        changed = False
        for index, alternatives in constraints:
            valid = [choice for choice in alternatives
                     if all(color in domains[register] for register, color in choice.items())]
            if not valid:
                raise ValueError(f"retail operands require incompatible virtual-register roles at index {index}")
            for register in valid[0]:
                allowed = {choice[register] for choice in valid}
                narrowed = domains[register] & allowed
                if narrowed != domains[register]:
                    domains[register] = narrowed
                    changed = True

    unresolved = {str(register): sorted(colors) for register, colors in domains.items() if len(colors) != 1}
    desired = {register: next(iter(colors)) for register, colors in domains.items() if len(colors) == 1}
    current = [node["prefix"][6] for node in capture["colored"]]
    projected = [desired.get(register, color) for register, color in enumerate(current)]
    collisions = []
    for register, node in enumerate(capture["graph"]):
        if node["prefix"][7] & 4:
            continue
        for neighbor in node["neighbors"]:
            if neighbor <= register or capture["graph"][neighbor]["prefix"][7] & 4:
                continue
            if projected[register] == projected[neighbor]:
                collisions.append([register, neighbor, projected[register]])
    return {
        "instruction_count": len(final), "constrained_virtual_registers": len(domains),
        "skipped_instruction_indices": skipped,
        "unresolved_colors": unresolved,
        "changes": [{"virtual": register, "current": current[register], "retail": color,
                     "instruction_indices": sorted(positions[register])}
                    for register, color in sorted(desired.items()) if color != current[register]],
        "projection_collisions": collisions,
        "retail_projection_valid_with_unmapped_colors_unchanged": not unresolved and not collisions,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    document = json.loads(args.capture.read_text())
    capture = load_capture(args.capture, args.function)
    target, _ = strucdiff.obj_paths(document["unit"])
    source = args.capture.parent / "traced.o"
    result = project(capture, strucdiff.text_lines(str(source), args.function),
                     strucdiff.text_lines(target, args.function))
    result.update(function=args.function, unit=document["unit"],
                  captured_object_sha256=capture["object_sha256"])
    print(f"{args.function}: {result['instruction_count']} instructions; "
          f"{len(result['changes'])} virtual registers need different colors")
    for change in result["changes"]:
        print(f"  v{change['virtual']}: r{change['current']} -> r{change['retail']} "
              f"({len(change['instruction_indices'])} instructions)")
    print("Retail projection valid with unmapped colors unchanged:",
          result["retail_projection_valid_with_unmapped_colors_unchanged"])
    if result["unresolved_colors"]:
        print("Unresolved colors:", result["unresolved_colors"])
    if result["projection_collisions"]:
        print("Interference collisions:", result["projection_collisions"])
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
