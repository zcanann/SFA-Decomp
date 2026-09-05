"""Link Tricky's C object into the matching game without changing build outputs.

An object can contain automatically inlined static bodies that retail's linker
discarded. This probe checks their actual link fate and the retained literal pool;
it does not strip or rewrite the object to improve an objdiff score.
"""

import argparse
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

import flag_probe


UNIT = "main/dlls/objects/196_Tricky/tricky"
ROOT = Path(flag_probe.ROOT)


def link_inputs(query):
    inputs = []
    reading = False
    for line in query.splitlines():
        if line.startswith("  input:"):
            reading = True
        elif line.startswith("  outputs:"):
            break
        elif reading and line.startswith("    "):
            value = line.strip()
            if not value.startswith("|"):
                inputs.append(value.replace("\\", "/"))
    if not inputs:
        raise ValueError("ninja reported no explicit link inputs")
    return inputs


def replace_object(inputs, target, source):
    target = str(target).replace("\\", "/")
    if inputs.count(target) != 1:
        raise ValueError("expected exactly one retail Tricky link input")
    return [str(source).replace("\\", "/") if item == target else item for item in inputs]


def object_info(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        functions = {
            s.name: (s["st_value"], s["st_size"])
            for s in elf.get_section_by_name(".symtab").iter_symbols()
            if s["st_info"]["type"] == "STT_FUNC"
        }
        pool = elf.get_section_by_name(".sdata2").data()
    return functions, pool


def allocated_sections(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        return {
            section.name: (section["sh_addr"], section.data())
            for section in elf.iter_sections() if section["sh_flags"] & 2
        }


def section_differences(baseline, linked):
    differences = {}
    for name in sorted(baseline.keys() | linked.keys()):
        if name not in baseline or name not in linked:
            differences[name] = {"missing_from": "baseline" if name not in baseline else "linked"}
            continue
        base_address, base_data = baseline[name]
        link_address, link_data = linked[name]
        if base_address != link_address or base_data != link_data:
            differences[name] = {
                "baseline_address": hex(base_address),
                "linked_address": hex(link_address),
                "baseline_size": len(base_data),
                "linked_size": len(link_data),
                "changed_bytes": sum(a != b for a, b in zip(base_data, link_data))
                + abs(len(base_data) - len(link_data)),
            }
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", type=Path, default=ROOT / flag_probe.UNITS[UNIT]["base_path"])
    parser.add_argument("--output", type=Path, default=ROOT / "build/flag_probe/tricky_link")
    parser.add_argument("--baseline", type=Path, default=ROOT / "build/GSAE01/main.elf",
                        help="Existing matching-build ELF for whole-section comparison")
    args = parser.parse_args()
    source = args.object.resolve()
    output = args.output.resolve()
    linked = output / "main.elf"
    if linked == args.baseline.resolve():
        raise ValueError("diagnostic output must not overwrite the baseline ELF")
    output.mkdir(parents=True, exist_ok=True)
    query = subprocess.run(
        ["ninja", "-t", "query", "build/GSAE01/main.elf"], cwd=ROOT,
        capture_output=True, text=True, check=True, timeout=30,
    )
    inputs = replace_object(link_inputs(query.stdout), flag_probe.UNITS[UNIT]["target_path"], source)
    response = output / "link.rsp"
    response.write_text("\n".join(f'"{item}"' for item in inputs), encoding="ascii")
    result = subprocess.run(
        [str(ROOT / "build/compilers/GC/1.3.2/mwldeppc.exe"), "-fp", "hardware",
         "-nodefaults", "-lcf", "build/GSAE01/ldscript.lcf", "-o", str(linked), f"@{response}"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    (output / "link.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    result.check_returncode()
    retail, _ = object_info(ROOT / flag_probe.UNITS[UNIT]["target_path"])
    compiled, pool = object_info(source)
    final, final_pool = object_info(linked)
    extra = compiled.keys() - retail.keys()
    print("Extra object functions stripped:", sorted(extra - final.keys()))
    print("Extra object functions retained:", sorted(extra & final.keys()))
    print("Missing retail functions:", sorted(retail.keys() - final.keys()))
    print("Retail function size differences:", {
        name: (size, final[name][1]) for name, (_, size) in retail.items()
        if name in final and size != final[name][1]
    })
    print("Complete object literal pool retained:", pool in final_pool, f"({len(pool)} bytes)")
    if args.baseline.is_file():
        _, baseline_pool = object_info(args.baseline)
        print("Whole .sdata2 bytes equal baseline ELF:", final_pool == baseline_pool,
              f"({len(final_pool)}/{len(baseline_pool)} bytes)")
        print("Allocated-section differences against baseline ELF:",
              section_differences(allocated_sections(args.baseline), allocated_sections(linked)))
    else:
        print("Baseline ELF missing; whole-section comparison unavailable:", args.baseline)
    print("Linked ELF:", linked)
    print("This is a diagnostic link, not a matching-DOL verdict.")


if __name__ == "__main__":
    main()
