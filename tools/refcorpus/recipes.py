"""Per-project compile recipes for the GC/2.0 reference-asm corpus.

Each reference decomp is recompiled with SFA's own compiler (MWCC GC/2.0) and SFA's
own base flags, so the emitted asm is representative of *our* codegen rather than the
shape the project's original toolchain produced. We are NOT byte-matching the reference
binary; we're cataloguing "what does GC/2.0 do with this C" for shape lookups.

A recipe is pure data + an optional stub-header generator. `build_corpus.py` consumes it.
Adding a new project (e.g. Mickey's Speedway, once a decomp exists) is one RECIPES entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
REF_ROOT = REPO_ROOT / "reference_projects"
SHIM = "tools/refcorpus/shims/n64_mwcc.h"  # relative to REPO_ROOT (wibo needs relative)
COMPILER = "build/compilers/GC/2.0/mwcceppc.exe"
WIBO = "build/tools/wibo"
OBJDUMP = "build/binutils/powerpc-eabi-objdump"
GEN_ROOT = "build/refcorpus/gen"  # generated stub headers live here, prepended to -i
OUT_ROOT = "build/refcorpus"

# SFA main-lib base flags (from build.ninja), minus the per-file -i/-D and the -opt axis
# (which the profile supplies) and -maxerrors (the builder supplies). Passed as argv, so
# `-pragma "cats off"` is two argv items and needs no shell quoting.
BASE_CFLAGS: List[str] = [
    "-nodefaults", "-proc", "gekko", "-align", "powerpc", "-enum", "int",
    "-fp", "hardware", "-Cpp_exceptions", "off", "-O4,p", "-inline", "auto",
    "-pragma", "cats off", "-pragma", "warn_notinlined off",
    "-nosyspath", "-RTTI", "off", "-fp_contract", "on", "-str", "reuse",
    "-multibyte", "-lang=c",
]

# The one axis the corpus sweeps: the four peephole x scheduling combinations SFA toggles.
# `both_off` is SFA's global default (turned on per-function via #pragma in real source).
PROFILES: Dict[str, List[str]] = {
    "both_off": ["-opt", "nopeephole,noschedule"],
    "peep_on":  ["-opt", "peephole,noschedule"],
    "sched_on": ["-opt", "nopeephole,schedule"],
    "both_on":  ["-opt", "peephole,schedule"],
}


@dataclass
class Recipe:
    name: str                      # short id + corpus dir name (dkr/jfg/mp4)
    root: str                      # path under reference_projects/
    kind: str                      # "n64" or "gc" (affects shim/_LANGUAGE_C/char)
    src_globs: List[str]           # globs under root
    include_dirs: List[str]        # dirs under root, added as -i (in order)
    defines: List[str]             # NAME or NAME=VAL, added as -D
    exclude_res: List[str] = field(default_factory=list)  # regexes on rel path -> skip
    auto_src_subdirs: bool = True  # also -i every immediate subdir of each src glob root
    char_unsigned: bool = False
    use_shim: bool = False
    gen: Optional[str] = None      # key into GENERATORS

    @property
    def abs_root(self) -> Path:
        return REF_ROOT / self.root


# ---------------------------------------------------------------------------
# Stub-header generators. N64 decomps pull in headers generated from the ROM
# (asset_enums.h etc.) which we don't have. We harvest the identifiers the source
# references and emit a stub so GC/2.0 can compile the surrounding logic. Values are
# NOT rom-accurate -- irrelevant for a shape corpus (immediates differ, shapes don't).
# ---------------------------------------------------------------------------

_ASSET_TYPE_RE = re.compile(r"\bAsset[A-Za-z0-9]*Enum\b")
_ASSET_CONST_RE = re.compile(r"\bASSET_[A-Z0-9_]+\b")


def _gen_asset_enums(recipe: "Recipe") -> Dict[str, str]:
    types: set[str] = set()
    consts: set[str] = set()
    for p in recipe.abs_root.rglob("*"):
        if p.suffix in (".c", ".h") and "libultra" not in p.parts:
            try:
                txt = p.read_text(errors="ignore")
            except OSError:
                continue
            types.update(_ASSET_TYPE_RE.findall(txt))
            consts.update(_ASSET_CONST_RE.findall(txt))
    lines = ["#ifndef REFCORPUS_ASSET_ENUMS_H", "#define REFCORPUS_ASSET_ENUMS_H",
             "/* refcorpus stub: auto-harvested asset identifiers; values are not",
             "   rom-accurate, only present so GC/2.0 compiles the surrounding logic. */"]
    for t in sorted(types):
        lines.append(f"typedef int {t};")
    if consts:
        lines.append("enum {")
        lines.append("    REFCORPUS_ASSET_ENUM_ZERO = 0,")
        for c in sorted(consts):
            lines.append(f"    {c},")
        lines.append("};")
    lines.append("#endif")
    return {"asset_enums.h": "\n".join(lines) + "\n"}


GENERATORS: Dict[str, Callable[["Recipe"], Dict[str, str]]] = {
    "asset_enums": _gen_asset_enums,
}


# ---------------------------------------------------------------------------
# Recipes. Include dirs / defines mirror each project's own build (Makefile /
# configure.py); calibrated empirically against GC/2.0 (see docs/refcorpus.md).
# ---------------------------------------------------------------------------

_N64_LIBULTRA = [
    "libultra", "libultra/src/gu", "libultra/src/libc", "libultra/src/io",
    "libultra/src/sc", "libultra/src/audio", "libultra/src/os",
]

RECIPES: Dict[str, Recipe] = {
    "dkr": Recipe(
        name="dkr", root="dkr", kind="n64",
        src_globs=["src/**/*.c"],
        include_dirs=["", "include", "include/libc", "include/PR", "include/sys", "src"]
        + _N64_LIBULTRA,
        defines=["_FINALROM", "NDEBUG", "TARGET_N64", "F3DDKR_GBI", "VERSION_us_v77",
                 "BUILD_VERSION=4", "BUILD_VERSION_STRING=2.0G", "_MIPS_SZLONG=32",
                 "_LANGUAGE_C"],
        exclude_res=[r"/libultra/"],
        char_unsigned=True, use_shim=True, gen="asset_enums",
    ),
    "jfg": Recipe(
        name="jfg", root="jfg", kind="n64",
        src_globs=["src/**/*.c"],
        include_dirs=["", "include", "include/libc", "include/PR", "include/sys", "src",
                      "src/hasm/ido"] + _N64_LIBULTRA,
        defines=["_FINALROM", "NDEBUG", "TARGET_N64", "F3DDKR_GBI", "VERSION_us",
                 "BUILD_VERSION=6", "BUILD_VERSION_STRING=2.0I", "_MIPS_SZLONG=32",
                 "RAREDIFFS", "JFGDIFFS", "_LANGUAGE_C"],
        exclude_res=[r"/libultra/"],
        char_unsigned=True, use_shim=True, gen="asset_enums",
    ),
    "mp4": Recipe(
        name="mp4", root="marioparty4", kind="gc",
        src_globs=["src/game/**/*.c", "src/**/*.c"],
        include_dirs=["", "include", "extern/musyx/include", "src"],  # "" = root, for REL unity includes
        defines=["VERSION=0", "VERSION_GSAE01", "BUILD_VERSION=0", "NDEBUG=1"],
        # skip the SDK/runtime/MSL trees: lower signal, and some need generated headers
        exclude_res=[r"/dolphin/", r"/Runtime", r"/MSL_C", r"/msm/", r"/OdemuExi2/",
                     r"/amcstubs/", r"/odenotstub/"],
        char_unsigned=False, use_shim=False, gen=None,
    ),
}


def resolve(names: Optional[List[str]]) -> List[Recipe]:
    if not names:
        return list(RECIPES.values())
    out = []
    for n in names:
        if n not in RECIPES:
            raise SystemExit(f"unknown project '{n}'. known: {', '.join(RECIPES)}")
        out.append(RECIPES[n])
    return out
