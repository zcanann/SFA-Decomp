#!/usr/bin/env python3
"""Compile small MWCC snippets and print their small data literal order."""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SJISWRAP = ROOT / "build" / "tools" / "sjiswrap.exe"
MWCC = ROOT / "build" / "compilers" / "GC" / "2.0" / "mwcceppc.exe"
OBJDUMP = ROOT / "build" / "binutils" / "powerpc-eabi-objdump.exe"

FLAGS = [
    "-nodefaults",
    "-proc",
    "gekko",
    "-align",
    "powerpc",
    "-enum",
    "int",
    "-fp",
    "hardware",
    "-Cpp_exceptions",
    "off",
    "-O4,p",
    "-inline",
    "auto",
    "-pragma",
    "cats off",
    "-pragma",
    "warn_notinlined off",
    "-maxerrors",
    "1",
    "-nosyspath",
    "-RTTI",
    "off",
    "-fp_contract",
    "on",
    "-str",
    "reuse",
    "-multibyte",
    "-i",
    str(ROOT / "include"),
    "-i",
    str(ROOT / "build" / "GSAE01" / "include"),
    "-DBUILD_VERSION=0",
    "-DVERSION_GSAE01",
    "-DNDEBUG=1",
    "-opt",
    "nopeephole,noschedule,nopropagation",
    "-inline",
    "noauto",
    "-lang=c",
]

PRELUDE = """\
typedef float f32;
typedef signed int s32;

typedef struct Obj {
    signed short rotX;
    f32 x;
} Obj;

extern void sinkf(f32);
"""

VARIANTS: dict[str, str] = {
    "literal_current": """
int fn(Obj* obj, f32 a) {
    int acc = 0;
    if (a > 0.0001f) {
        acc += 1;
    }
    if (a > 2.5f) {
        acc += 2;
    } else if (a > 0.66f) {
        acc += 3;
    } else if (a > 0.33f) {
        acc += 4;
    }
    sinkf(3.1415927f * ((f32)(s32)obj->rotX / 32768.0f));
    sinkf(0.04f);
    sinkf(15.0f);
    return acc;
}
""",
    "tricky_like_singletons_before": """
const f32 pi[1] = {3.1415927f};
const f32 half[1] = {32768.0f};

#define PI pi[0]
#define HALF half[0]

static inline void face(Obj* obj) {
    sinkf(PI * ((f32)(s32)obj->rotX / HALF));
}

const f32 eps[1] = {0.0001f};
const f32 run[1] = {2.5f};
const f32 fast[1] = {0.66f};
const f32 slow[1] = {0.33f};
const f32 turn[1] = {0.04f};
const f32 frames[1] = {15.0f};

int fn(Obj* obj, f32 a) {
    int acc = 0;
    if (a > eps[0]) {
        acc += 1;
    }
    face(obj);
    if (a > run[0]) {
        acc += 2;
    } else if (a > fast[0]) {
        acc += 3;
    } else if (a > slow[0]) {
        acc += 4;
    }
    sinkf(turn[0]);
    sinkf(frames[0]);
    return acc;
}
""",
    "extern_singletons_after_function": """
const f32 pi[1] = {3.1415927f};
const f32 half[1] = {32768.0f};
extern const f32 eps[1];
extern const f32 run[1];
extern const f32 fast[1];
extern const f32 slow[1];
extern const f32 turn[1];
extern const f32 frames[1];

#define PI pi[0]
#define HALF half[0]

static inline void face(Obj* obj) {
    sinkf(PI * ((f32)(s32)obj->rotX / HALF));
}

int fn(Obj* obj, f32 a) {
    int acc = 0;
    if (a > eps[0]) {
        acc += 1;
    }
    face(obj);
    if (a > run[0]) {
        acc += 2;
    } else if (a > fast[0]) {
        acc += 3;
    } else if (a > slow[0]) {
        acc += 4;
    }
    sinkf(turn[0]);
    sinkf(frames[0]);
    return acc;
}

const f32 eps[1] = {0.0001f};
const f32 run[1] = {2.5f};
const f32 fast[1] = {0.66f};
const f32 slow[1] = {0.33f};
const f32 turn[1] = {0.04f};
const f32 frames[1] = {15.0f};
""",
    "extern_pairs_after_function": """
const f32 pi[1] = {3.1415927f};
const f32 half[1] = {32768.0f};
extern const f32 speedTuning[2];
extern const f32 walkTuning[2];
extern const f32 animTuning[2];

#define PI pi[0]
#define HALF half[0]

static inline void face(Obj* obj) {
    sinkf(PI * ((f32)(s32)obj->rotX / HALF));
}

int fn(Obj* obj, f32 a) {
    int acc = 0;
    if (a > speedTuning[0]) {
        acc += 1;
    }
    face(obj);
    if (a > speedTuning[1]) {
        acc += 2;
    } else if (a > walkTuning[0]) {
        acc += 3;
    } else if (a > walkTuning[1]) {
        acc += 4;
    }
    sinkf(animTuning[0]);
    sinkf(animTuning[1]);
    return acc;
}

const f32 speedTuning[2] = {0.0001f, 2.5f};
const f32 walkTuning[2] = {0.66f, 0.33f};
const f32 animTuning[2] = {0.04f, 15.0f};
""",
    "static_singletons_after_function": """
const f32 pi[1] = {3.1415927f};
const f32 half[1] = {32768.0f};
static const f32 eps[1];
static const f32 run[1];
static const f32 fast[1];
static const f32 slow[1];
static const f32 turn[1];
static const f32 frames[1];

#define PI pi[0]
#define HALF half[0]

static inline void face(Obj* obj) {
    sinkf(PI * ((f32)(s32)obj->rotX / HALF));
}

int fn(Obj* obj, f32 a) {
    int acc = 0;
    if (a > eps[0]) {
        acc += 1;
    }
    face(obj);
    if (a > run[0]) {
        acc += 2;
    } else if (a > fast[0]) {
        acc += 3;
    } else if (a > slow[0]) {
        acc += 4;
    }
    sinkf(turn[0]);
    sinkf(frames[0]);
    return acc;
}

static const f32 eps[1] = {0.0001f};
static const f32 run[1] = {2.5f};
static const f32 fast[1] = {0.66f};
static const f32 slow[1] = {0.33f};
static const f32 turn[1] = {0.04f};
static const f32 frames[1] = {15.0f};
""",
}


def run(cmd: list[str]) -> str:
    proc = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.stdout)
    return proc.stdout


def dump_words(obj: Path, section: str) -> list[str]:
    out = run([str(OBJDUMP), "-s", "-j", section, str(obj)])
    words: list[str] = []
    for line in out.splitlines():
        m = re.match(r"\s*[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{8}\s+)+)", line)
        if m:
            words.extend(m.group(1).split())
    return words


def compile_variant(tmp: Path, name: str, body: str) -> Path:
    src = tmp / f"{name}.c"
    src.write_text(PRELUDE + "\n" + body, encoding="ascii")
    run([str(SJISWRAP), str(MWCC), *FLAGS, "-c", str(src), "-o", str(tmp)])
    return tmp / f"{name}.o"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("variant", nargs="*")
    parser.add_argument("--sections", nargs="+", default=[".sdata2", ".sdata", ".rodata"])
    args = parser.parse_args()

    unknown = sorted(set(args.variant) - set(VARIANTS))
    if unknown:
        raise SystemExit(f"unknown variant(s): {', '.join(unknown)}")

    names = args.variant or sorted(VARIANTS)
    with tempfile.TemporaryDirectory(prefix="mwcc-pool-") as td:
        tmp = Path(td)
        for name in names:
            obj = compile_variant(tmp, name, VARIANTS[name])
            print(name)
            for section in args.sections:
                try:
                    words = dump_words(obj, section)
                except SystemExit:
                    words = []
                print(f"  {section}:")
                for idx, word in enumerate(words):
                    print(f"    {idx:02d}: {word}")


if __name__ == "__main__":
    main()
