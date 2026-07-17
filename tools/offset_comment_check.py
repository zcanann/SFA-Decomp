#!/usr/bin/env python3
"""Verify /* 0xNN: */ field-offset comments against the real struct layout.

No gate sees these claims: STATIC_ASSERT anchors only a few fields per struct,
so a padding edit silently falsifies every offset comment below it. This uses
the real compiler as the oracle (never a hand-rolled type-size model) by
emitting STATIC_ASSERT(offsetof(S, f) == CLAIMED) for every commented field.

Usage:  python3 tools/offset_comment_check.py [header ...]
        (no args = sweep every header carrying an offset comment)

Exit 0 = every claim verified; exit 1 = at least one header failed.

Two known false-positive shapes, both requiring a human read of the hit:
  - a sub-location note on a padding block: `u8 pad04[0x38]; /* 0x18: ... */`
    documents an offset INSIDE the pad, not the pad's own offset. Legitimate
    when start <= claim < start+size; a claim outside that span is a real bug.
  - a header that will not compile standalone (missing type dep) reports as
    FAIL_BUILD, which is a harness gap and not a false comment.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CC = [
    "build/tools/wibo", "build/tools/sjiswrap.exe",
    "build/compilers/GC/2.0/mwcceppc.exe",
    "-nodefaults", "-proc", "gekko", "-align", "powerpc", "-enum", "int",
    "-fp", "hardware", "-Cpp_exceptions", "off", "-O4,p", "-inline", "auto",
    "-pragma", "cats off", "-pragma", "warn_notinlined off",
    "-maxerrors", "200", "-nosyspath", "-RTTI", "off", "-fp_contract", "on",
    "-str", "reuse", "-multibyte", "-i", "include", "-i", "build/GSAE01/include",
    "-DBUILD_VERSION=0", "-DVERSION_GSAE01", "-DNDEBUG=1", "-lang=c",
]

TYPEDEF_RE = re.compile(r"typedef\s+struct\s*(\w+)?\s*\{(.*?)\}\s*(\w+)\s*;", re.S)
# Only a COLON form is an offset claim. `/* 0x80 = caught in beam */` is a BIT
# mask and `/* obj+0xC0 swap slot */` names the value's source, not this field.
FIELD_RE = re.compile(
    r"\s*(?:const\s+)?([A-Za-z_][\w ]*?[\w*])\s+(\*?\w+)\s*(\[[^;]*\])?\s*;"
    r"\s*/\*\s*0x([0-9A-Fa-f]{1,4})\s*:"
)


def strip_nested(body):
    """Drop nested union/anon-struct regions; their fields need a scoped path."""
    out, depth = [], 0
    for ch in body:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def probes_for(header):
    src = re.sub(r"//.*", "", open(header, encoding="utf-8", errors="replace").read())
    found = []
    for m in TYPEDEF_RE.finditer(src):
        tag = m.group(3)
        for line in strip_nested(m.group(2)).split("\n"):
            fm = FIELD_RE.match(line)
            if not fm or ":" in line.split("/*")[0]:  # skip bitfields
                continue
            found.append((tag, fm.group(2).lstrip("*"), int(fm.group(4), 16)))
    return found


def check(header):
    probes = probes_for(header)
    if not probes:
        return "SKIP", 0, ""
    inc = header.split("include/", 1)[-1]
    lines = ['#include "global.h"', '#include "main/game_object.h"', f'#include "{inc}"']
    for i, (tag, name, off) in enumerate(probes):
        lines.append(
            f"char probe_{i}[(offsetof({tag},{name})==0x{off:X})?1:-1]; "
            f"/* {tag}.{name} @0x{off:X} */"
        )
    with tempfile.TemporaryDirectory() as td:
        cf = os.path.join(td, "probe.c")
        open(cf, "w").write("\n".join(lines) + "\n")
        r = subprocess.run(
            CC + ["-c", cf, "-o", os.path.join(td, "probe.o")],
            cwd=ROOT, capture_output=True, text=True,
        )
        out = r.stdout + r.stderr
    if "Error" not in out:
        return "CLEAN", len(probes), ""
    bad = re.findall(r"offsetof\(([A-Za-z_]\w*),(\w+)\)==0x([0-9A-Fa-f]+)", out)
    if not bad:
        return "FAIL_BUILD", len(probes), out.strip().split("\n")[-1]
    return "FAIL", len(probes), "; ".join(f"{s}.{f} claims 0x{o}" for s, f, o in bad)


def main():
    argv = sys.argv[1:]
    if argv:
        headers = argv
    else:
        headers = sorted(
            os.path.join(dp, fn)
            for dp, _, fns in os.walk(os.path.join(ROOT, "include"))
            for fn in fns
            if fn.endswith(".h")
            and re.search(
                r"/\* ?0x[0-9A-Fa-f]{1,4} ?:",
                open(os.path.join(dp, fn), encoding="utf-8", errors="replace").read(),
            )
        )
    total, bad = 0, 0
    for h in headers:
        rel = os.path.relpath(h, ROOT)
        status, n, detail = check(h)
        if status == "CLEAN":
            total += n
        elif status != "SKIP":
            bad += 1
            print(f"{status:10s} {rel} ({n} probes)  {detail}")
    print(f"\n{total} offset claims verified TRUE; {bad} header(s) need a look.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
