"""Per-project compile recipes for the GC/2.0 reference-asm corpus.

Each reference decomp is recompiled with SFA's own compiler (MWCC GC/2.0) and SFA's
own base flags, so the emitted asm is representative of *our* codegen rather than the
shape the project's original toolchain produced. We are NOT byte-matching the reference
binary; we're cataloguing "what does GC/2.0 do with this C" for shape lookups.

A recipe is data plus optional generated-header and source-transform hooks.
`build_corpus.py` consumes it. Adding a new project (e.g. Mickey's Speedway, once a
decomp exists) is one RECIPES entry.
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
    name: str                      # short id + corpus dir name (dkr/jfg/mp4/melee)
    root: str                      # path under reference_projects/
    kind: str                      # "n64" or "gc" (affects shim/_LANGUAGE_C/char)
    src_globs: List[str]           # globs under root
    include_dirs: List[str]        # dirs under root, added as -i (in order)
    defines: List[str]             # NAME or NAME=VAL, added as -D
    extra_flags: List[str] = field(default_factory=list)  # recipe-wide argv after defines
    exclude_res: List[str] = field(default_factory=list)  # regexes on rel path -> skip
    auto_src_subdirs: bool = True  # also -i every immediate subdir of each src glob root
    include_source_dir: bool = False  # put each C file's own dir first in -i search order
    char_unsigned: bool = False
    relax_pointers: bool = False  # accept permissive IDO-era pointer-to-pointer conversions
    use_shim: bool = False
    gen: Optional[str] = None      # key into GENERATORS
    transform: Optional[str] = None  # key into TRANSFORMS; generated copy, never source edit
    source_flags: Dict[str, List[str]] = field(default_factory=dict)  # rel-path regex -> argv

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


def _gen_mp4_assets(recipe: "Recipe") -> Dict[str, str]:
    """Emit size/alignment-correct definitions for opaque disc-extracted arrays.

    Mario Party 4's config maps each generated .inc name to its symbol. The retail
    bytes are deliberately unavailable in a source-only clone, but using a one-byte
    stand-in can move an object into SDA and alter the instructions that address it.
    Preserve the exact object size and alignment from the version's symbol files;
    selected C only takes these symbols' addresses or indexes them at runtime.
    """
    config = recipe.abs_root / "config/GMPE01_00/config.yml"
    mapped_headers: Dict[str, str] = {}
    symbol: Optional[str] = None
    for line in config.read_text(errors="ignore").splitlines():
        match = re.match(r"\s*- symbol:\s*([A-Za-z_]\w*)\s*$", line)
        if match:
            symbol = match.group(1)
            continue
        match = re.match(r"\s*header:\s*([^\s#]+\.inc)\s*$", line)
        if match and symbol:
            mapped_headers[match.group(1)] = symbol
            symbol = None

    needed_symbols = set(mapped_headers.values())
    metadata: Dict[str, tuple[int, Optional[int]]] = {}
    symbol_root = recipe.abs_root / "config/GMPE01_00"
    for symbols_file in symbol_root.rglob("symbols.txt"):
        for line in symbols_file.read_text(errors="ignore").splitlines():
            match = re.match(r"\s*([A-Za-z_]\w*)\s*=.*?;\s*//(.*)$", line)
            if not match or match.group(1) not in needed_symbols:
                continue
            meta = match.group(2)
            size_match = re.search(r"\bsize:(0x[0-9A-Fa-f]+|\d+)\b", meta)
            if not size_match:
                continue
            align_match = re.search(r"\balign:(0x[0-9A-Fa-f]+|\d+)\b", meta)
            value = (int(size_match.group(1), 0),
                     int(align_match.group(1), 0) if align_match else None)
            old = metadata.get(match.group(1))
            if old is not None and old != value:
                raise RuntimeError(
                    f"conflicting MP4 symbol metadata for {match.group(1)}: {old} vs {value}"
                )
            metadata[match.group(1)] = value

    headers: Dict[str, str] = {}
    for header, symbol in mapped_headers.items():
        if symbol not in metadata:
            raise RuntimeError(
                f"MP4 generated asset {header} ({symbol}) has no size metadata under "
                f"{symbol_root}"
            )
        size, align = metadata[symbol]
        alignment = f" ATTRIBUTE_ALIGN({align})" if align is not None else ""
        headers[header] = (
            "/* refcorpus stub: retail bytes opaque; exact size/alignment preserved. */\n"
            f"unsigned char {symbol}[{size}]{alignment} = {{ 0 }};\n"
        )
    return headers


GENERATORS: Dict[str, Callable[["Recipe"], Dict[str, str]]] = {
    "asset_enums": _gen_asset_enums,
    "mp4_assets": _gen_mp4_assets,
}


def _transform_dkr_c89(recipe: "Recipe", rel: str, text: str) -> str:
    """Apply narrow syntax/type repairs for known IDO-to-GC/2.0 differences."""
    if rel == "src/debug.c":
        text = text.replace(
            "void debug_dump_hex(u8 *var, s32 size, s32 lineWidth) {\n"
            "    for (int i = 0; i < size; i++) {",
            "void debug_dump_hex(u8 *var, s32 size, s32 lineWidth) {\n"
            "    int i;\n"
            "    for (i = 0; i < size; i++) {",
        )
        text = text.replace(
            "void debug_thread(s32 field, s32 offset) {\n"
            "    DebugData *d = gDebug;",
            "void debug_thread(s32 field, s32 offset) {\n"
            "    DebugData *d = gDebug;\n"
            "    s32 count;",
        ).replace("    s32 count = field >> 1;", "    count = field >> 1;")
    elif rel == "src/objects.c":
        text = text.replace(
            "camera = cam_get_active_camera_no_cutscenes();\n"
            "                            // we need the camera to be a s32",
            "camera = (s32) cam_get_active_camera_no_cutscenes();\n"
            "                            // we need the camera to be a s32",
        )
    elif rel == "src/thread0_epc.c":
        for name in ("TEXT", "DATA", "RODATA", "BSS"):
            for suffix in ("START", "END", "SIZE"):
                if name == "BSS" and suffix == "START":
                    continue
                text = text.replace(
                    f"extern u8 *main_{name}_{suffix}[];",
                    f"extern u8 main_{name}_{suffix}[];",
                )
        text = text.replace("(u32) main_BSS_START", "(u32) (u8 *) main_BSS_START")
    return text


def _transform_jfg_c89(recipe: "Recipe", rel: str, text: str) -> str:
    """Make explicit the 32-bit pointer conversions accepted by the native IDO build."""
    replacements = {
        "src/anim.c": [
            ("D_8010549C = *arg0;", "D_8010549C = (u8 *) *arg0;"),
        ],
        "src/charControl.c": [
            ("return &player->pad68[0x90];", "return (s32) &player->pad68[0x90];"),
            ("return &player->pad68[0x2E];", "return (s32) &player->pad68[0x2E];"),
        ],
        "src/lights.c": [
            ("initColourCycle(arg0 + 0x48, arg1);",
             "initColourCycle((unkResetColourCycle *) (arg0 + 0x48), arg1);"),
            ("func_80021444(D_800A1898[i], arg0);",
             "func_80021444((unk800DC950 *) D_800A1898[i], arg0);"),
            ("return D_800A1898;", "return (unk800DC950 **) D_800A1898;"),
        ],
        "src/runLink.c": [
            ("return addressBase + (romTableEntry->entry.FunctionOffset) + addressOffset;",
             "return (void *) (addressBase + romTableEntry->entry.FunctionOffset + addressOffset);"),
            ("return var_v1;", "return (void *) var_v1;"),
            ("return (patchLocation->jump.target << 2) + overlayTable[otIndex].VramBase;",
             "return (void *) ((patchLocation->jump.target << 2) + overlayTable[otIndex].VramBase);"),
            ("address = TrapDanglingJump;", "address = (u32) TrapDanglingJump;"),
        ],
    }
    for old, new in replacements.get(rel, []):
        text = text.replace(old, new)
    return text


TRANSFORMS: Dict[str, Callable[["Recipe", str, str], str]] = {
    "dkr_c89": _transform_dkr_c89,
    "jfg_c89": _transform_jfg_c89,
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
                 "_LANGUAGE_C", "ANTI_TAMPER=1", "CIC_ID=6103", "SRAM=1"],
        # debug.c is the real unity TU for src/usb/*.c. The other exclusions are
        # assembly-only, data-only, or a target-ISA stack-pointer intrinsic.
        exclude_res=[r"/libultra/", r"/src/usb/", r"/src/hasm/collision\.c$",
                     r"/src/screen_asset\.c$", r"/src/unused_string\.c$",
                     r"/src/os_yield_data\.c$", r"/src/get_stack_pointer\.c$"],
        include_source_dir=True,
        char_unsigned=True, relax_pointers=True, use_shim=True, gen="asset_enums",
        transform="dkr_c89",
    ),
    "jfg": Recipe(
        name="jfg", root="jfg", kind="n64",
        src_globs=["src/**/*.c"],
        include_dirs=["", "include", "include/libc", "include/PR", "include/sys", "src",
                      "src/hasm/ido"] + _N64_LIBULTRA,
        defines=["_FINALROM", "NDEBUG", "TARGET_N64", "F3DDKR_GBI", "VERSION_us",
                 "BUILD_VERSION=6", "BUILD_VERSION_STRING=2.0I", "_MIPS_SZLONG=32",
                 "RAREDIFFS", "JFGDIFFS", "_LANGUAGE_C"],
        # Kiosk overlays are wrong-version placeholders under the US recipe;
        # diCpuTraceCurrentStack is a target-MIPS stack-pointer intrinsic.
        exclude_res=[r"/libultra/", r"/src/overlays_kiosk/",
                     r"/src/diCpuTraceCurrentStack\.c$"],
        include_source_dir=True,
        char_unsigned=True, relax_pointers=True, use_shim=True, gen="asset_enums",
        transform="jfg_c89",
    ),
    "mp4": Recipe(
        name="mp4", root="marioparty4", kind="gc",
        src_globs=["src/game/**/*.c", "src/**/*.c"],
        include_dirs=["", "include", "extern/musyx/include", "src"],  # "" = root, for REL unity includes
        defines=["VERSION=0", "MUSY_TARGET=MUSY_TARGET_DOLPHIN", "NDEBUG=1"],
        # skip the SDK/runtime/MSL trees: lower signal, and some need generated headers
        exclude_res=[r"/dolphin/", r"/Runtime", r"/MSL_C", r"/msm/", r"/OdemuExi2/",
                     r"/amcstubs/", r"/odenotstub/", r"/TRK_MINNOW_DOLPHIN/",
                     r"/src/game/font\.c$",
                     r"/src/game/ovllist\.c$", r"/src/REL/empty\.c$",
                     r"/src/REL/bootDll/language\.c$", r"/src/REL/executor\.c$"],
        include_source_dir=True,
        char_unsigned=True, use_shim=False, gen="mp4_assets",
        source_flags={r"/src/REL/m450Dll/main\.c$": ["-pool", "off"]},
    ),
    "mp4_musyx": Recipe(
        name="mp4_musyx", root="marioparty4", kind="gc",
        # These are the 31 Dolphin runtime units selected by MP4's native build.
        # The remaining runtime sources are PC, profiling, or alternate-platform
        # implementations and are deliberately not mixed into this family.
        src_globs=["extern/musyx/src/musyx/runtime/**/*.c"],
        include_dirs=["include", "extern/musyx/include"],
        defines=["MUSY_TARGET=MUSY_TARGET_DOLPHIN", "MUSY_VERSION_MAJOR=1",
                 "MUSY_VERSION_MINOR=5", "MUSY_VERSION_PATCH=4"],
        extra_flags=["-fp", "hard", "-str", "reuse,pool,readonly",
                     "-fp_contract", "off"],
        exclude_res=[r"/extern/musyx/src/musyx/runtime/hw_lib_dolphin\.c$",
                     r"/extern/musyx/src/musyx/runtime/hw_pc\.c$",
                     r"/extern/musyx/src/musyx/runtime/profile\.c$"],
        auto_src_subdirs=False,
    ),
    "mp4_msm": Recipe(
        name="mp4_msm", root="marioparty4", kind="gc",
        src_globs=["src/msm/**/*.c"],
        include_dirs=["include", "extern/musyx/include", "src"],
        defines=["VERSION=0", "MUSY_TARGET=MUSY_TARGET_DOLPHIN", "NDEBUG=1"],
        # MP4's MSM library uses the common game base flags without the game's
        # unsigned-char override. Keep it isolated from the main MP4 recipe.
        auto_src_subdirs=False,
        include_source_dir=True,
    ),
    "melee": Recipe(
        name="melee", root="melee", kind="gc",
        src_globs=["src/melee/**/*.c", "src/sysdolphin/**/*.c"],
        include_dirs=["", "src", "src/MSL", "src/Runtime",
                      "src/melee", "src/melee/ft/chara", "src/sysdolphin",
                      "extern/dolphin/include"],
        defines=["BUILD_VERSION=0", "VERSION_GALE01"],
        # Keep this focused on game and HSD code. The project compiler/runtime/MSL
        # trees use distinct library flags and mostly duplicate lower-signal samples
        # already present in other GameCube reference projects.
        exclude_res=[],
        auto_src_subdirs=False,
        include_source_dir=True,
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
