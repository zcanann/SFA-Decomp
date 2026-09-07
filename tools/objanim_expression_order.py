"""Reproduce ObjAnim's GC/1.3 expression/register ordering tradeoff in isolation.

    python3 tools/objanim_expression_order.py --trace

The reduced C kernel is a compiler experiment, not retail source. It retains
the index wrap, repeated cursor assignments, and earlier progress use that
are absent from a straight-line two-curve expression. The configured ObjAnim
compiler command is reused without modifying production flags or sources.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import flag_probe
import strucdiff
from compiler_command import split_command_line
from tricky_backend_ir import COMPILER_SHA256
from tricky_source_order_probe import compile_command


ROOT = Path(__file__).resolve().parents[1]
UNIT = "main/main/objanim"
FUNCTION = "sampleRootDelta"
ASSIGNMENT = "moveDistanceDelta = moveRootScale * ((f32)axisSamples[1] - axisSamples[0]);"
STAGED = "curveProgress = (f32)axisSamples[1] - axisSamples[0];\n                moveDistanceDelta = moveRootScale * curveProgress;"


def summarize(assembly):
    """Locate the blended accumulation, rejecting a changed instruction shape."""
    mnemonics = [line.split()[0] for line in assembly]
    sums = [i for i in range(1, len(assembly) - 1) if mnemonics[i - 1:i + 2] == ["fmuls", "fmadds", "fadds"]]
    if len(sums) != 1:
        raise ValueError("expected one blended accumulation in the reduced kernel")
    products = [i for i in range(sums[0]) if mnemonics[i] == "fmuls"]
    if len(products) < 3:
        raise ValueError("missing reduced-kernel scale/weight multiplications")
    move, blend, weight = products[-3:]
    addresses = [i for i in range(move - 1, blend) if mnemonics[i] == "add"]
    if len(addresses) != 1 or weight + 1 != sums[0]:
        raise ValueError("reduced-kernel blend address/weight sequence changed")
    biases = [i for i in range(move) if mnemonics[i] == "lfd" and "<" in assembly[i]]
    if not biases:
        raise ValueError("missing integer-to-float conversion bias")
    destination = lambda i: re.search(r"\bf(\d+),", assembly[i]).group(1)
    return {"instruction_count": len(assembly), "move_product_index": move,
            "blend_address_index": addresses[0], "bias_register": "f" + destination(biases[-1]),
            "move_product_register": "f" + destination(move)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=ROOT / "tools/fixtures/objanim_expression_order.c")
    parser.add_argument("--output", type=Path, default=ROOT / "build/flag_probe/objanim_expression_order")
    parser.add_argument("--trace", action="store_true", help="Also capture frontend propagation under macOS LLDB")
    args = parser.parse_args()
    if args.trace and sys.platform != "darwin":
        parser.error("--trace requires macOS LLDB and Wibo")
    source = args.source.read_text()
    if source.count(ASSIGNMENT) != 1:
        parser.error("source must contain exactly one reduced-kernel move-product assignment")
    base = split_command_line(flag_probe.base_cmd(UNIT))
    compiler = next(ROOT / value for value in base if Path(value).name.lower() == "mwcceppc.exe")
    if hashlib.sha256(compiler.read_bytes()).hexdigest() != COMPILER_SHA256:
        raise ValueError("compiler does not match the GC/1.3 decoder profile")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").unlink(missing_ok=True)
    report = {"compiler_sha256": COMPILER_SHA256, "unit": UNIT, "variants": {}}
    for name, text in [("named", source), ("staged", source.replace(ASSIGNMENT, STAGED))]:
        directory = output / name
        directory.mkdir(parents=True, exist_ok=True)
        candidate = directory / "objanim_expression_order.c"
        if candidate == args.source.resolve():
            parser.error("output must be separate from the input source")
        candidate.write_text(text)
        obj = candidate.with_suffix(".o")
        obj.unlink(missing_ok=True)
        candidate.with_suffix(".s").unlink(missing_ok=True)
        command = compile_command(base, candidate, directory)
        subprocess.run(command, cwd=ROOT, check=True, timeout=30, capture_output=True)
        assembly = strucdiff.text_lines(str(obj), FUNCTION)
        candidate.with_suffix(".s").write_text("\n".join(assembly) + "\n")
        item = summarize(assembly)
        item.update(source_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
                    object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(), command=command)
        report["variants"][name] = item
        print(f"{name}: {item['instruction_count']} instructions; bias {item['bias_register']}; "
              f"move product {item['move_product_register']} at {item['move_product_index']}; "
              f"blend address at {item['blend_address_index']}", flush=True)
        if args.trace:
            subprocess.run([sys.executable, str(ROOT / "tools/mwcc_frontend_trace.py"), "--unit", UNIT,
                            "--function", FUNCTION, "--source", str(candidate), "--output", str(directory / "frontend"),
                            "--propagation"], cwd=ROOT, check=True)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Report:", output / "report.json")


if __name__ == "__main__":
    main()
