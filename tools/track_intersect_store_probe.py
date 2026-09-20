#!/usr/bin/env python3
"""Reproduce trackGetIntersect2's two residual frame-address folds.

Compile complete scratch TUs with the configured flags, score with objdiff,
and optionally capture the baseline and volatile diagnostic through LLDB.
The volatile variant is a compiler experiment, not recovered game source.
Nothing is installed into src/ or promoted to Matching.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import flag_probe
import strucdiff
from compiler_command import split_command_line
from tricky_backend_ir import COMPILER_SHA256, decode
from tricky_backend_trace import run_capture
from tricky_object_compare import compare_objects, read_object
from tricky_source_order_probe import compile_command


ROOT = Path(__file__).resolve().parents[1]
UNIT = "main/main/track_dolphin"
FUNCTION = "trackGetIntersect2"
SOURCE = ROOT / "src/main/track_dolphin.c"
STORES = "                    *endY = cur[1];\n                    *endZ = cur[2] - offZ;"
VOLATILE_STORES = STORES.replace("*endY", "*(volatile f32*)endY").replace("*endZ", "*(volatile f32*)endZ")


def variants(source):
    if source.count(VOLATILE_STORES) == 1 and STORES not in source:
        source = source.replace(VOLATILE_STORES, STORES)
    if source.count(STORES) != 1:
        raise ValueError("expected exactly one static-world endpoint store pair")
    yield "baseline", source
    yield "pointer_cast", source.replace(
        STORES, STORES.replace("*endY", "*(f32*)endY").replace("*endZ", "*(f32*)endZ")
    )
    yield "local_alias", source.replace(
        STORES,
        "                    {\n"
        "                        f32* y = endY;\n"
        "                        f32* z = endZ;\n"
        "                        *y = cur[1];\n"
        "                        *z = cur[2] - offZ;\n"
        "                    }",
    )
    yield "array_access", source.replace(
        STORES, STORES.replace("*endY", "we[1]").replace("*endZ", "we[2]")
    )
    # Preserve line numbers so the independent captures can be compared by
    # source location, without assuming arena addresses survive across runs.
    yield "volatile_diagnostic", source.replace(STORES, VOLATILE_STORES)


def store_stages(document, lines):
    """Expose flags and operands around the observed constant-propagation pass."""
    snapshots = document["snapshots"]
    indices = [i for i, s in enumerate(snapshots) if s["stage"] == "AFTER CONSTANT PROPAGATION"]
    if len(indices) != 1 or indices[0] == 0:
        raise ValueError("expected one constant-propagation stage with a predecessor")
    result = []
    for snapshot in snapshots[indices[0] - 1:indices[0] + 1]:
        stores = []
        for block in snapshot["blocks"]:
            for instruction in block["instructions"]:
                decoded = decode(instruction)
                if decoded["opcode"] == 0x96 and decoded["line"] in lines:
                    stores.append({
                        "line": decoded["line"],
                        "flags": hex(instruction["words"][5]),
                        "operands": decoded["operands"],
                    })
        if sorted(s["line"] for s in stores) != sorted(lines):
            raise ValueError("could not uniquely identify both stores in the capture")
        result.append({"stage": snapshot["stage"], "stores": stores})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/track_intersect_store_probe")
    parser.add_argument("--capture", action="store_true", help="also capture baseline and diagnostic optimizer stages")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_bytes()
    text = source.decode()
    source_hash = hashlib.sha256(source).hexdigest()
    base = split_command_line(flag_probe.base_cmd(UNIT))
    compiler = next(ROOT / token for token in base if Path(token).name.lower() == "mwcceppc.exe")
    if hashlib.sha256(compiler.read_bytes()).hexdigest() != COMPILER_SHA256:
        raise ValueError("this experiment requires the verified GC/1.3 compiler")
    baseline_text = next(variants(text))[1]
    first_line = baseline_text[:baseline_text.index(STORES)].count("\n") + 1
    report = {
        "schema": 1, "function": FUNCTION, "unit": UNIT,
        "source_sha256": source_hash, "compiler_sha256": COMPILER_SHA256,
        "caveat": "Volatile is a diagnostic control; exact output does not establish original-source provenance.",
        "variants": {},
    }
    # Every invocation owns fresh objects and captures, even when --output is
    # reused. Failed compiles can never satisfy checks using old artifacts.
    with tempfile.TemporaryDirectory(prefix="compile-", dir=output) as temporary:
        baseline = None
        for name, candidate in variants(text):
            directory = Path(temporary) / name
            directory.mkdir()
            path = directory / SOURCE.name
            path.write_text(candidate)
            command = compile_command(base, path, directory)
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True, timeout=30)
            obj = directory / "track_dolphin.o"
            snapshot = read_object(obj)
            if baseline is None:
                baseline = snapshot
            scores, error = flag_probe.score(UNIT, str(obj))
            if error:
                raise ValueError(error)
            rows, retail, current, target_count, current_count = strucdiff.analyse(UNIT, FUNCTION, str(obj))
            differences = [
                {"retail_index": a, "current_index": b,
                 "retail": retail[a] if a is not None else None,
                 "current": current[b] if b is not None else None}
                for marker, a, b in rows if marker != " "
            ]
            retained = output / name
            retained.mkdir(exist_ok=True)
            (retained / SOURCE.name).write_text(candidate)
            (retained / obj.name).write_bytes(obj.read_bytes())
            item = {
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "command": command, "object_sha256": snapshot.digest,
                "objdiff_percent": scores[1][FUNCTION],
                "target_instructions": target_count, "current_instructions": current_count,
                "differences": differences, "baseline_comparison": compare_objects(baseline, snapshot),
            }
            if args.capture and name in ("baseline", "volatile_diagnostic"):
                document, _ = run_capture(path, retained / "capture", [FUNCTION], unit=UNIT)
                if document["object_sha256"] != snapshot.digest:
                    raise ValueError("capture differs from the scored object")
                item["constant_propagation"] = store_stages(document, [first_line, first_line + 1])
            report["variants"][name] = item
            print(f"{name}: {item['objdiff_percent']:.6f}%; {current_count} instructions; "
                  f"{len(differences)} differences", flush=True)
    if SOURCE.read_bytes() != source:
        raise RuntimeError("production source changed during the experiment; rerun against a stable source")
    destination = output / "report.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Report: {destination}\n{report['caveat']}")


if __name__ == "__main__":
    main()
