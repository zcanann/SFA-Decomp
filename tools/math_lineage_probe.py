#!/usr/bin/env python3
"""Search reference source/assembly literals for the older SFA math coefficients.

This is candidate discovery, not a library identity test. Decimal literals are
rounded to binary32; hex words are also considered as raw binary32 bits. Sign
is ignored to accommodate unary minus and subtraction. Comments are removed.
Expressions, encoded double-word pairs, missing/dead-stripped functions, and
unavailable library versions are outside the search.

    python3 tools/math_lineage_probe.py reference_projects/melee /path/to/sms
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("src/main/acosf.c", "src/main/trig.c",
           "src/MSL_C/PPCEABI/bare/H/math_float_helpers.c")
NUMBERS = re.compile(
    r"(?<![\w.])(?:0[xX][0-9a-fA-F]+|(?:\d+\.\d*|\.\d+|\d+)"
    r"(?:[eE][+-]?\d+)?)(?:[fFlLuU]*)(?![\w.])")


def float_bits(value):
    return struct.unpack(">I", struct.pack(">f", value))[0] & 0x7FFFFFFF


def fingerprints():
    result, inputs = {}, []
    for source in SOURCES:
        data = (ROOT / source).read_bytes()
        inputs.append(dict(source=source, sha256=hashlib.sha256(data).hexdigest()))
        for name, value in re.findall(r"const float (\w+) = ([^;]+);", data.decode()):
            if not re.search("Coeff|Linear|Cubic|Quintic|Septic|Quadratic|Quartic|Sextic|Octic|Bias", name):
                continue
            word = float_bits(float(value.rstrip("f")))
            result.setdefault(word, []).append(name)
    return result, inputs


def scan(root, wanted):
    count, hits = 0, []
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in (".c", ".cpp", ".h", ".hpp", ".s", ".inc") or not path.is_file():
            continue
        count += 1
        text = re.sub(r"/\*.*?\*/|//[^\n]*", "", path.read_text(errors="replace"), flags=re.S)
        found = set()
        for match in NUMBERS.finditer(text):
            token = match[0]
            try:
                if token.lower().startswith("0x"):
                    word = int(token.rstrip("uUlL"), 16) & 0x7FFFFFFF
                else:
                    word = float_bits(float(token.rstrip("fFlLuU")))
            except (ValueError, OverflowError):
                continue
            if word in wanted:
                found.add(word)
        if found:
            hits.append(dict(path=str(path.relative_to(root)),
                             constants=[dict(bits=f"{word:08x}", names=wanted[word]) for word in sorted(found)]))
    return dict(root=str(root), files=count, hits=hits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, default=ROOT / "build/math-lineage-references/coefficient-scan.json")
    args = parser.parse_args()
    wanted, inputs = fingerprints()
    rows = []
    for root in args.roots:
        if not root.is_dir():
            parser.error(f"reference directory does not exist: {root}")
        row = scan(root, wanted)
        rows.append(row)
        print(f"{root}: {row['files']} files, {len(row['hits'])} candidate files", flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(inputs=inputs,
        constants={f"{word:08x}": names for word, names in wanted.items()}, projects=rows), indent=2) + "\n")


if __name__ == "__main__":
    main()
