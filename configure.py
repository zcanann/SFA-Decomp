#!/usr/bin/env python3

###
# Generates build files for the project.
# This file also includes the project configuration,
# such as compiler flags and the object matching status.
#
# Usage:
#   python3 configure.py
#   ninja
#
# Append --help to see available options.
###

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

from tools.project import (
    Object as ProjectObject,
    ProgressCategory,
    ProjectConfig,
    calculate_progress,
    generate_build,
    is_windows,
)

# Retain the public type name for annotations until the matching-aware factory
# below replaces it for object construction.
Object = ProjectObject

# Game versions
DEFAULT_VERSION = 0
VERSIONS = [
    "GSAE01",  # 0
    "GSAJ01",  # 1
    "GSAP01",  # 2
    "GSAE01_rev1",  # 3
    "GSAP01_rev1",  # 4
]


def parse_version(value: str) -> str:
    for version in VERSIONS:
        if value.upper() == version.upper():
            return version
    raise argparse.ArgumentTypeError(f"unknown version: {value}")


parser = argparse.ArgumentParser()
parser.add_argument(
    "mode",
    choices=["configure", "progress"],
    default="configure",
    help="script mode (default: configure)",
    nargs="?",
)
parser.add_argument(
    "-v",
    "--version",
    choices=VERSIONS,
    type=parse_version,
    default=VERSIONS[DEFAULT_VERSION],
    help="version to build",
)
parser.add_argument(
    "--build-dir",
    metavar="DIR",
    type=Path,
    default=Path("build"),
    help="base build directory (default: build)",
)
parser.add_argument(
    "--binutils",
    metavar="BINARY",
    type=Path,
    help="path to binutils (optional)",
)
parser.add_argument(
    "--compilers",
    metavar="DIR",
    type=Path,
    help="path to compilers (optional)",
)
parser.add_argument(
    "--map",
    action="store_true",
    help="generate map file(s)",
)
parser.add_argument(
    "--debug",
    action="store_true",
    help="build with debug info (non-matching)",
)
if not is_windows():
    parser.add_argument(
        "--wrapper",
        metavar="BINARY",
        type=Path,
        help="path to wibo or wine (optional)",
    )
parser.add_argument(
    "--dtk",
    metavar="BINARY | DIR",
    type=Path,
    help="path to decomp-toolkit binary or source (optional)",
)
parser.add_argument(
    "--objdiff",
    metavar="BINARY | DIR",
    type=Path,
    help="path to objdiff-cli binary or source (optional)",
)
parser.add_argument(
    "--sjiswrap",
    metavar="EXE",
    type=Path,
    help="path to sjiswrap.exe (optional)",
)
parser.add_argument(
    "--ninja",
    metavar="BINARY",
    type=Path,
    help="path to ninja binary (optional)",
)
parser.add_argument(
    "--verbose",
    action="store_true",
    help="print verbose output",
)
parser.add_argument(
    "--non-matching",
    dest="non_matching",
    action="store_true",
    help="builds equivalent (but non-matching) or modded objects",
)
parser.add_argument(
    "--matching",
    dest="non_matching",
    action="store_false",
    help="build matching objects and use the hash-checked default target",
)
parser.add_argument(
    "--warn",
    dest="warn",
    type=str,
    choices=["all", "off", "error"],
    help="how to handle warnings",
)
parser.add_argument(
    "--no-progress",
    dest="progress",
    action="store_false",
    help="disable progress calculation",
)
parser.add_argument(
    "--zlb-toolchain",
    dest="zlb_toolchain",
    type=str,
    choices=["prodg", "mwcc"],
    default="prodg",
    help="compiler for src/main/zlb.c; mwcc is a diagnostic comparison path "
    "only (retail is GCC-family)",
)
parser.add_argument(
    "--prodg-version",
    dest="prodg_version",
    type=str,
    default="3.5",
    help="ProDG release under build/compilers/ProDG when --zlb-toolchain=prodg",
)
parser.set_defaults(non_matching=True)
args = parser.parse_args()

config = ProjectConfig()
config.version = str(args.version)
version_num = VERSIONS.index(config.version)
if not args.non_matching and config.version != "GSAE01":
    sys.exit(
        f"{config.version} currently supports progress reports only; "
        "omit --matching (EN v1.0 remains the strict matching target)"
    )

# Apply arguments
config.build_dir = args.build_dir
config.dtk_path = args.dtk
config.objdiff_path = args.objdiff
config.binutils_path = args.binutils
config.compilers_path = args.compilers
config.generate_map = args.map
config.non_matching = args.non_matching
config.sjiswrap_path = args.sjiswrap
config.ninja_path = args.ninja
if config.ninja_path is None:
    ninja_path = shutil.which("ninja")
    if ninja_path is not None:
        config.ninja_path = Path(ninja_path)
config.progress = args.progress
# Only the active EN target has a supported final link and checksum.  Regional
# configurations still compile every source unit and generate objdiff progress
# reports, but their progress target must not force an unsupported DOL link.
config.progress_requires_link = config.version == "GSAE01"
if not is_windows():
    config.wrapper = args.wrapper
# Don't build asm unless we're --non-matching
if not config.non_matching:
    config.asm_dir = None

# Tool versions
config.binutils_tag = "2.42-1"
config.compilers_tag = "20251118"
config.dtk_tag = "v1.8.0"
config.objdiff_tag = "v3.5.1"
config.sjiswrap_tag = "v1.2.2"
config.wibo_tag = "1.1.0"

# Project
config.config_path = Path("config") / config.version / "config.yml"
config.check_sha_path = Path("config") / config.version / "build.sha1"
config.asflags = [
    "-mgekko",
    "--strip-local-absolute",
    "-I include",
    f"-I build/{config.version}/include",
    f"--defsym BUILD_VERSION={version_num}",
]
config.ldflags = [
    "-fp hardware",
    "-nodefaults",
]
if args.debug:
    config.ldflags.append("-g")  # Or -gdwarf-2 for Wii linkers
if args.map:
    config.ldflags.append("-mapunused")
    # config.ldflags.append("-listclosure") # For Wii linkers

# Use for any additional files that should cause a re-configure when modified
config.reconfig_deps = []
config.split_deps = [
    Path("config") / config.version / "splits.txt",
    Path("config") / config.version / "symbols.txt",
]
symbol_mappings_path = Path("config") / config.version / "symbol_mappings.json"
if symbol_mappings_path.is_file():
    config.symbol_mappings = json.loads(symbol_mappings_path.read_text(encoding="utf-8"))
    config.reconfig_deps.append(symbol_mappings_path)
matching_units_path = Path("config") / config.version / "matching_units.txt"
matching_units = set()
if matching_units_path.is_file():
    matching_units = {
        line.strip()
        for line in matching_units_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    config.reconfig_deps.append(matching_units_path)

# Optional numeric ID for decomp.me preset
# Can be overridden in libraries or objects
config.scratch_preset_id = None

# Foreign-toolchain rules. zlbDecompress is GCC-family, not MWCC: retail
# carries "mcrxr cr0; addme." doloops, an idiom absent from the whole GC/2.0
# refcorpus. The vintage is OLDER than anything vendored here - all five SN
# ProDG releases (3.5, 3.5b140, 3.7, 3.8.1, 3.9.3) emit byte-identical
# prologues that open stwu-before-mflr on 8-byte-aligned frames, while retail
# opens mflr-before-stwu on an 84-byte (4-aligned) frame. --prodg-version
# selects the release, so an acquired older cc1 can be tested by dropping it
# in build/compilers/ProDG/<ver>.
# NOTE: prologue shape alone does NOT discriminate MWCC from GCC - the matched
# MWCC twin modelApplyBoneTransform opens mflr/stwu/stw/stmw too. Only the
# mcrxr/addme idiom is decisive.
# NOTE: rule prodg hardcodes its flags and never consumes $cflags, so
# per-object cflags on this unit are silently discarded. The cc1 binary itself
# does honour flags (-O2/-Os/-fno-schedule-insns all change output); an earlier
# "cc1 ignores flags" note conflated the two.
prodg_compilers = Path(args.compilers) if args.compilers else Path("build/compilers")
prodg_binutils = Path(args.binutils) if args.binutils else Path("build/binutils")
prodg_as = prodg_binutils / ("powerpc-eabi-as.exe" if is_windows() else "powerpc-eabi-as")
prodg_dir = prodg_compilers / "ProDG" / args.prodg_version
if is_windows():
    prodg_wrapper = ""
    # Native Windows ninja runs commands without an implicit shell, so the
    # "&&" chain must be wrapped in cmd /c (mirrors the mwcc_*extab rules).
    prodg_shell = "cmd /c "
else:
    prodg_wrapper = f"{args.wrapper} " if args.wrapper else "build/tools/wibo "
    prodg_shell = ""
prodg_implicit = [
    str(prodg_compilers) if args.compilers is None else str(prodg_dir / "cc1.exe"),
    str(prodg_binutils) if args.binutils is None else str(prodg_as),
    *([prodg_wrapper.strip()] if prodg_wrapper else []),
]
config.custom_build_rules = [
    {
        "name": "prodg",
        "command": f"{prodg_shell}{prodg_wrapper}{prodg_dir / 'cpp.exe'} -Iinclude -P $in $basefile.i"
        f" && {prodg_wrapper}{prodg_dir / 'cc1.exe'} $basefile.i"
        " -quiet -O1 -fno-common -frerun-loop-opt -frerun-cse-after-loop -o $basefile.s"
        f" && {prodg_as} -mgekko $basefile.s -o $out",
        "description": "PRODG $out",
    },
]

if args.zlb_toolchain == "prodg":
    zlb_object_kwargs = {
        "custom_rule": "prodg",
        "custom_rule_implicit": prodg_implicit,
    }
else:
    zlb_object_kwargs = {}

# Base flags, common to most GC/Wii games.
# Generally leave untouched, with overrides added below.
cflags_base = [
    "-nodefaults",
    "-proc gekko",
    "-align powerpc",
    "-enum int",
    "-fp hardware",
    "-Cpp_exceptions off",
    # "-W all",
    "-O4,p",
    "-inline auto",
    '-pragma "cats off"',
    '-pragma "warn_notinlined off"',
    "-maxerrors 1",
    "-nosyspath",
    "-RTTI off",
    "-fp_contract on",
    "-str reuse",
    "-multibyte",  # For Wii compilers, replace with `-enc SJIS`
    "-i include",
    f"-i build/{config.version}/include",
    f"-DBUILD_VERSION={version_num}",
    f"-DVERSION_{config.version}",
]

# Debug flags
if args.debug:
    # Or -sym dwarf-2 for Wii compilers
    cflags_base.extend(["-sym on", "-DDEBUG=1"])
else:
    cflags_base.append("-DNDEBUG=1")

# Warning flags
if args.warn == "all":
    cflags_base.append("-W all")
elif args.warn == "off":
    cflags_base.append("-W off")
elif args.warn == "error":
    cflags_base.append("-W error")

# Metrowerks library flags
cflags_runtime = [
    *cflags_base,
    "-use_lmw_stmw on",
    "-str reuse,pool,readonly",
    "-gccinc",
    "-common off",
    "-inline auto",
]

cflags_runtime_125 = [flag for flag in cflags_runtime if flag != "-gccinc"]

# Game/DLL TUs the original build compiled with the scheduler and peephole
# passes off (a per-TU compiler setting, not a per-function one).
cflags_game = [*cflags_base, "-char signed"]

cflags_dll_noopt = [
    *cflags_game,
    "-opt", "nopeephole,noschedule",
]

# ...plus auto-inlining off: functions marked `inline` are still inlined, but
# small non-inline helpers are not auto-inlined (matches the original build,
# which emits calls to trivial getters like Music_GetActivePriority).
cflags_dll_noopt_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule",
    "-inline", "noauto",
]

cflags_dll_noopt_noautoinline_alwaysinline = [
    *cflags_dll_noopt_noautoinline,
    '-pragma "always_inline on"',
]

cflags_dll_noopt_noautoinline_level3 = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,level=3",
    "-inline", "noauto",
]

cflags_dll_noopt_level1 = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,level=1",
]

cflags_dll_noopt_level2 = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,level=2",
]

cflags_dll_noopt_noautoinline_deferred = [
    *cflags_game,
    "-opt", "nopeephole,noschedule",
    "-inline", "noauto,deferred",
]

cflags_dll_nosched = [
    *cflags_game,
    "-opt", "noschedule",
]

cflags_dll_noopt_nostrength = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nostrength",
]

cflags_dll_noopt_nostrength_noautoinline = [
    *cflags_dll_noopt_nostrength,
    "-inline", "noauto",
]

cflags_dll_noopt_nolifetimes_noloopinv_nostrength = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nolifetimes,noloopinvariants,nostrength",
]

cflags_dll_noopt_nocse_nolifetimes_noloopinv_noprop_nostrength = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,nolifetimes,noloopinvariants,nopropagation,nostrength",
]

# ...plus common-subexpression elimination off (opt_common_subs off).
cflags_dll_noopt_nocse = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse",
]

# ...plus inlining off (dont_inline on).
cflags_dll_noopt_nocse_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse",
    "-inline", "noauto",
]

cflags_dll_noopt_nodead_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nodead",
    "-inline", "noauto",
]

cflags_dll_noopt_nodead_noloopinv_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nodead,noloopinvariants",
    "-inline", "noauto",
]

cflags_dll_noopt_nocse_nodead_nofpcontract_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,nodead",
    "-inline", "noauto",
    "-fp_contract", "off",
]

cflags_dll_noopt_nocse_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse",
    "-inline", "off",
]

# ...plus copy/constant propagation off (opt_propagation off).
cflags_dll_noopt_noprop = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation",
]

# ...plus strength reduction off (keeps byte-array loop indices as a single indexed IV).
cflags_dll_noopt_noprop_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation",
    "-inline", "noauto",
]

cflags_dll_noopt_noprop_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation",
    "-inline", "noauto",
]

cflags_dll_noopt_noprop_nostrength = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation,nostrength",
]

cflags_dll_noopt_noprop_nostrength_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation,nostrength",
    "-inline", "noauto",
]

# ...plus loop-invariant code motion off (opt_loop_invariants off).
cflags_dll_noopt_noloopinv = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,noloopinvariants",
]

cflags_dll_noopt_noloopinv_noautoinline = [
    *cflags_dll_noopt_noloopinv,
    "-inline", "noauto",
]

cflags_dll_noopt_noloopinv_noprop_nospecunroll_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,noloopinvariants,nopropagation",
    "-inline", "noauto",
    '-pragma "ppc_unroll_speculative off"',
]


cflags_dll_noopt_noloopinv_zerodata = [
    *cflags_dll_noopt_noloopinv,
    '-pragma "explicit_zero_data on"',
]

cflags_dll_noopt_noloopinv_noprop_zerodata = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,noloopinvariants,nopropagation",
    '-pragma "explicit_zero_data on"',
]

# ...plus register-lifetime optimization off (opt_lifetimes off).
cflags_dll_noopt_nolifetimes_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nolifetimes",
    "-inline", "noauto",
]

cflags_dll_noopt_nocse_noprop_nolifetimes_zerodata_noautoinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,nopropagation,nolifetimes",
    '-pragma "explicit_zero_data on"',
    "-inline", "noauto",
]

cflags_dll_noopt_nolifetimes = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nolifetimes",
]

cflags_dll_noopt_noloopinv_nolifetimes = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,noloopinvariants,nolifetimes",
]

# ...plus dead-code elimination off (opt_dead_code off).
cflags_dll_noopt_noloopinv_nolifetimes_nodead = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,noloopinvariants,nolifetimes,nodead",
]

cflags_dll_noopt_noloopinv_nolifetimes_zerodata = [
    *cflags_dll_noopt_noloopinv_nolifetimes,
    '-pragma "explicit_zero_data on"',
]

cflags_dll_noopt_noloopinv_nolifetimes_noprop_zerodata = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,noloopinvariants,nolifetimes,nopropagation",
    '-pragma "explicit_zero_data on"',
]

cflags_dll_noopt_nocse_noloopinv_nolifetimes_noprop_zerodata = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,noloopinvariants,nolifetimes,nopropagation",
    '-pragma "explicit_zero_data on"',
]

cflags_dll_noopt_nolifetimes_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nolifetimes",
    "-inline", "off",
]

cflags_dll_nopeep = [
    *cflags_game,
    "-opt", "nopeephole",
]

# noopt (peephole+scheduler off) base, plus additional per-TU passes off.
cflags_dll_noopt_nocse_noprop = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,nopropagation",
]

cflags_dll_noopt_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule",
    "-inline", "off",
]

cflags_dll_noopt_noloopinv_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,noloopinvariants",
    "-inline", "off",
]

cflags_dll_noopt_nocse_noprop_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,nopropagation",
    "-inline", "off",
]

cflags_dll_noopt_nocse_noloopinv = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,noloopinvariants",
]

cflags_dll_noopt_nocse_noloopinv_noautoinline = [
    *cflags_dll_noopt_nocse_noloopinv,
    "-inline", "noauto",
]

cflags_dll_noopt_noprop_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation",
    "-inline", "off",
]

cflags_dll_noopt_nostrength_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nostrength",
    "-inline", "off",
]

cflags_dll_noopt_nocse_noprop_noloopinv_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,nopropagation,noloopinvariants",
    "-inline", "off",
]

cflags_msl = [
    *cflags_base,
    "-char signed",
    "-use_lmw_stmw on",
    "-str reuse,pool,readonly",
]

msl_math_extra = ["-schedule", "off"]
msl_math_o0_cflags = [flag for flag in cflags_base if flag != "-O4,p"]

# REL flags
cflags_rel = [
    *cflags_base,
    "-sdata 0",
    "-sdata2 0",
]

cflags_trk = [
    *cflags_base,
    "-sdata 0",
    "-sdata2 0",
    "-inline auto,deferred",
    "-rostr",
    "-char signed",
    "-use_lmw_stmw on",
    "-common off",
]

config.linker_version = "GC/1.3.2"


# Helper function for Dolphin libraries
def DolphinLib(lib_name: str, objects: List[Object]) -> Dict[str, Any]:
    return {
        "lib": lib_name,
        "mw_version": "GC/1.2.5n",
        "cflags": cflags_base,
        "progress_category": "sdk",
        "objects": objects,
    }


# Helper function for Metrowerks Standard Library objects
def MSLLib(lib_name: str, objects: List[Object]) -> Dict[str, Any]:
    return {
        "lib": lib_name,
        "mw_version": "GC/1.2.5n",
        "cflags": cflags_base,
        "progress_category": "third_party",
        "objects": objects,
    }


# Helper function for REL script objects
def Rel(lib_name: str, objects: List[Object]) -> Dict[str, Any]:
    return {
        "lib": lib_name,
        "mw_version": "GC/1.3.2",
        "cflags": cflags_rel,
        "progress_category": "game",
        "objects": objects,
    }


Matching = config.version == "GSAE01"  # Object matches and should be linked
NonMatching = False               # Object does not match and should not be linked
Equivalent = config.non_matching  # Object should be linked when configured with --non-matching


# Object is only matching for specific versions
def MatchingFor(*versions):
    return config.version in versions


def Object(completed, name, **options):
    """Apply generated cross-version exactness without duplicating every call."""

    return ProjectObject(completed or name in matching_units, name, **options)


config.warn_missing_config = True
config.warn_missing_source = False
config.libs = [
    {
        "lib": "Runtime.PPCEABI.H",
        "mw_version": config.linker_version,
        "cflags": cflags_runtime,
        "progress_category": "sdk",  # str | List[str]
        "objects": [
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__start.c", mw_version="GC/1.2.5n", cflags=cflags_runtime_125),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__mem.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/mem_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/__exception.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__va_arg.c"),
            Object(Matching, "Runtime.PPCEABI.H/global_destructor_chain.c"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/runtime.c"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__init_cpp_exceptions.cpp"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/fragment.c"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/GCN_mem_alloc.c"),
        ],
    },
    DolphinLib(
        "os",
        [
            Object(MatchingFor("GSAE01"), "dolphin/os/OS.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSAlarm.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSAlloc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSArena.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSAudioSystem.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSCache.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSContext.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSError.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSExec.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSFont.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSInterrupt.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSLink.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSMessage.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSMemory.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSMutex.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSReboot.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSReset.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSResetSW.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSRtc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSStopwatch.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSSync.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSThread.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSTime.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/__ppc_eabi_init.c"),
        ],
    ),
    DolphinLib(
        "base",
        [
            Object(MatchingFor("GSAE01"), "dolphin/base/PPCArch.c"),
        ],
    ),
    DolphinLib(
        "db",
        [
            Object(MatchingFor("GSAE01"), "dolphin/db/db.c"),
        ],
    ),
    DolphinLib(
        "mtx",
        [
            Object(MatchingFor("GSAE01"), "dolphin/mtx/mtx.c", source="dolphin/mtx/mtx.c", extra_cflags=["-DGEKKO"]),
            Object(MatchingFor("GSAE01"), "dolphin/mtx/mtxvec.c", source="dolphin/mtx/mtxvec.c"),
            Object(MatchingFor("GSAE01"), "dolphin/mtx/vec.c"),
            Object(MatchingFor("GSAE01"), "dolphin/mtx/mtx44.c"),
            Object(NonMatching, "dolphin/mtx/mtx44vec.c"),
            Object(MatchingFor("GSAE01"), "dolphin/mtx/psmtx.c"),
        ],
    ),
    DolphinLib(
        "dvd",
        [
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvdlow.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvdfs.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvd.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvdqueue.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvderror.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/fstload.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvdFatal.c"),
            Object(NonMatching, "dolphin/dvd/dvdidutils.c"),
        ],
    ),
    DolphinLib(
        "ai",
        [
            Object(MatchingFor("GSAE01"), "dolphin/ai/ai.c"),
        ],
    ),
    DolphinLib(
        "ar",
        [
            Object(MatchingFor("GSAE01"), "dolphin/ar/ar.c"),
            Object(MatchingFor("GSAE01"), "dolphin/ar/arq.c"),
        ],
    ),
    DolphinLib(
        "dsp",
        [
            Object(MatchingFor("GSAE01"), "dolphin/dsp/dsp.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dsp/dsp_task.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dsp/dsp_debug.c"),
        ],
    ),
    DolphinLib(
        "ax",
        [
            Object(MatchingFor("GSAE01"), "dolphin/ax/AX.c"),
            Object(NonMatching, "dolphin/ax/AXAlloc.c"),
            Object(NonMatching, "dolphin/ax/AXAux.c"),
            Object(NonMatching, "dolphin/ax/AXCL.c"),
            Object(NonMatching, "dolphin/ax/AXComp.c"),
            Object(NonMatching, "dolphin/ax/AXOut.c"),
            Object(NonMatching, "dolphin/ax/AXProf.c"),
            Object(NonMatching, "dolphin/ax/AXSPB.c"),
            Object(NonMatching, "dolphin/ax/AXVPB.c"),
        ],
    ),
    DolphinLib(
        "si",
        [
            Object(MatchingFor("GSAE01"), "dolphin/si/SIBios.c"),
            Object(MatchingFor("GSAE01"), "dolphin/si/SISamplingRate.c"),
        ],
    ),
    DolphinLib(
        "pad",
        [
            Object(MatchingFor("GSAE01"), "dolphin/pad/Padclamp.c"),
            Object(MatchingFor("GSAE01"), "dolphin/pad/Pad.c", extra_cflags=["-DVERSION_GCCP01"]),
        ],
    ),
    DolphinLib(
        "exi",
        [
            Object(MatchingFor("GSAE01"), "dolphin/exi/EXIBios.c"),
            Object(MatchingFor("GSAE01"), "dolphin/exi/EXIUart.c"),
        ],
    ),
    DolphinLib(
        "hio",
        [
            Object(NonMatching, "dolphin/hio/hio.c"),
        ],
    ),
    DolphinLib(
        "mcc",
        [
            Object(NonMatching, "dolphin/mcc/mcc.c"),
            Object(NonMatching, "dolphin/mcc/fio.c"),
        ],
    ),
    DolphinLib(
        "mix",
        [
            Object(NonMatching, "dolphin/mix/mix.c"),
        ],
    ),
    DolphinLib(
        "gx",
        [
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXInit.c", extra_cflags=["-opt", "nopeephole"]),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXFifo.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXMisc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXLight.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTexture.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXBump.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXAttr.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXDisplayList.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXFrameBuf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXDraw.c", extra_cflags=["-fp_contract", "off"]),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXPerf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXPixel.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXSave.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXStubs.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTev.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTransform.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXGeometry.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXVerifRAS.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXVerifXF.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXVerify.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXVert.c"),
        ],
    ),
    DolphinLib(
        "card",
        [
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDBios.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDUnlock.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDRdwr.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDBlock.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDDir.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDCheck.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDMount.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDFormat.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDOpen.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDCreate.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDRead.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDWrite.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDDelete.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDStat.c"),
            Object(MatchingFor("GSAE01"), "dolphin/card/CARDNet.c"),
        ],
    ),
    DolphinLib(
        "axfx",
        [
            Object(NonMatching, "dolphin/axfx/chorus.c"),
            Object(NonMatching, "dolphin/axfx/delay.c"),
            Object(NonMatching, "dolphin/axfx/reverb_hi.c"),
            Object(NonMatching, "dolphin/axfx/reverb_hi_4ch.c"),
            Object(MatchingFor("GSAE01"), "dolphin/axfx/reverb_std_callback.c", extra_cflags=["-Cpp_exceptions", "on"]),
            Object(NonMatching, "dolphin/axfx/reverb_std.c"),
            Object(MatchingFor("GSAE01"), "dolphin/axfx/reverb_std_create.c"),
        ],
    ),
    {
        "lib": "vi",
        "mw_version": "GC/1.2.5n",
        "cflags": [
            *cflags_base,
            "-use_lmw_stmw on",
        ],
        "progress_category": "sdk",
        "objects": [
            Object(MatchingFor("GSAE01"), "dolphin/vi/vi.c"),
            Object(NonMatching, "dolphin/vi/gpioexi.c"),
            Object(NonMatching, "dolphin/vi/i2c.c"),
            Object(NonMatching, "dolphin/vi/initphilips.c"),
        ],
    },
    DolphinLib(
        "thp",
        [
            Object(MatchingFor("GSAE01"), "dolphin/thp/THPDec.c", mw_version="GC/1.2.5"),
            Object(MatchingFor("GSAE01"), "dolphin/thp/THPAudio.c"),
        ],
    ),
    {
        "lib": "OdemuExi2",
        "mw_version": "GC/1.2.5",
        "cflags": cflags_base,
        "progress_category": "sdk",
        "objects": [
            Object(MatchingFor("GSAE01"), "dolphin/OdemuExi2/DebuggerDriver.c"),
        ],
    },
    DolphinLib(
        "odenotstub",
        [
            Object(MatchingFor("GSAE01"), "dolphin/odenotstub/odenotstub.c"),
        ],
    ),
    {
        "lib": "amcstubs",
        "mw_version": "GC/1.3",
        "cflags": cflags_trk,
        "progress_category": "sdk",
        "objects": [
            Object(MatchingFor("GSAE01"), "dolphin/amcstubs/AmcExi2Stubs.c"),
        ],
    },
    {
        "lib": "TRK_MINNOW_DOLPHIN",
        "mw_version": "GC/1.3",
        "cflags": cflags_trk,
        "progress_category": "sdk",
        "objects": [
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mainloop.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/nubevent.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/nubinit.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msg.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msgbuf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/serpoll.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/usr_put.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/dispatch.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msghndlr.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/support.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mutex_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/notify.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/flush_cache.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mem_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targimpl.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targsupp.s"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mpc_7xx_603e.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/main_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk_glue.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targcont.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/target_options.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mslsupp.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/MWCriticalSection_gc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/main.c", progress_category="sdk"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/CircleBuffer.c", progress_category="sdk"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/main_gdev.c", progress_category="sdk"),
        ],
    },
    MSLLib(
        "MSL_C",
        [
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/abort_exit.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/alloc.c", mw_version="GC/1.3", cflags=cflags_msl, extra_cflags=["-common", "off", "-inline", "auto,deferred"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/ansi_files.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/ansi_fp.c", mw_version="GC/1.3", extra_cflags=["-inline", "all", "-inline", "auto,deferred", "-use_lmw_stmw", "on", "-char", "signed", "-str", "pool,readonly"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/buffer_io.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/direct_io.c", mw_version="GC/1.3", extra_cflags=["-use_lmw_stmw", "on"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/file_io.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/FILE_POS.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/mbstring.c", mw_version="GC/1.3.2r", cflags=cflags_msl),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/mem.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/mem_funcs.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/misc_io.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/printf.c", mw_version="GC/1.3", extra_cflags=["-use_lmw_stmw", "on", "-char", "signed"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/string.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/wchar_io.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/ctype.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_copysign.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_frexp.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_ldexp.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_modf.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/base/PPCArch_weak.c", progress_category="sdk"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/ctype_funcs.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/uart_console_io_gcn.c", mw_version="GC/1.2.5"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/hyperbolicsf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/floorf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/math_ppc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_cos.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_atan.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/e_acos.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/e_fmod.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/exponentialsf.c", extra_cflags=["-O3,p", "-opt", "nopeephole", "-sdata", "0"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/extras.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/k_rem_pio2.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_acos.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_atan2.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_fmod.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_pow.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_sqrt.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/common_float_tables.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/trigf.c", mw_version="GC/1.2.5"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.c", extra_cflags=["-inline", "off", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/math_802927a4.c", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", "-use_lmw_stmw", "on", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/math_80293da4.c", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "functions,peephole", "-inline", "auto", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/math_8029454c.c", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "functions,peephole", "-inline", "auto", "-sym", "on", *msl_math_extra], progress_category="game"),
        ],
    ),
    {
        "lib": "musyx",
        "mw_version": "GC/1.2.5n",
        "cflags": [
            *cflags_base,
            "-Cpp_exceptions", "on",
        ],
        "progress_category": "third_party",
        "objects": [
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_callback.c"),
            Object(NonMatching, "musyx/runtime/synth_queue.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_channel.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_handle.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_seq_events.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_sequence.c"),
            Object(NonMatching, "musyx/runtime/synth_seq_dispatch.c", extra_cflags=["-fp_contract", "off"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/mcmd_data.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_seq_queue.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth.c", extra_cflags=["-fp_contract", "off"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_control.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/snd_synth_api.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_job_init.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_jobs.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/data_tables.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/mcmd_wait.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/mcmd_loop.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/mcmd_setup.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/mcmd_volume.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/mcmd_exec.c", extra_cflags=["-inline", "noauto"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/pitch_data.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/adsr_data.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/voice.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_ac.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_adsr.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/synth_vsamples.c"),
            Object(Matching, "musyx/runtime/snd_groups.c", extra_cflags=["-inline", "noauto"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/sal_studio.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_dspctrl.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/sal_volume.c", extra_cflags=["-fp_contract", "off", "-inline", "all"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/snd3dgroup.c", extra_cflags=["-fp_contract", "off", "-inline", "noauto"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/snd_core.c", extra_cflags=["-fp_contract", "off"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/snd_midictrl.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/snd_service.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_init.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_break.c", mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_adsr.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_sample.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_voice_start.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_keyoff.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_voice_params.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_volume.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_input.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_stream.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_aram.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/hw_samplemem.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/aram_queue.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/aram_init.c", section_alignments={".bss": 4}),
            Object(MatchingFor("GSAE01"), "musyx/runtime/aram_data.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/sal_ai.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/sal_dsp.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/sal_dsp_irqinit.c", extra_cflags=["-opt", "noschedule"]),
            Object(MatchingFor("GSAE01"), "musyx/runtime/sal_dsp_irq.c"),
            Object(MatchingFor("GSAE01"), "musyx/runtime/snd_reverb.c"),
        ],
    },
    {
        "lib": "main",
        "mw_version": "GC/1.3",
        "cflags": cflags_dll_noopt,
        "progress_category": "game",
            "objects": [
            # dlls/engine
            # GC/1.3 retains the retail loader's post-store pointer reloads.
            # See docs/engine_0_matching.md for the whole-TU comparison.
            Object(NonMatching, "dlls/engine/0/0.c", extra_cflags=["-inline", "noauto", "-char", "signed"]),
            Object(NonMatching, "dlls/engine/1_camcontrol/camcontrol.c", mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/engine/2/maketex.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/2/2.c", cflags=cflags_dll_noopt_noloopinv_noautoinline, mw_version="GC/2.0"),
            Object(NonMatching, "dlls/engine/3/3.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/engine/4/4.c"),
            Object(NonMatching, "dlls/engine/5/5.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/6/6.c"),
            Object(NonMatching, "dlls/engine/7/7.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/engine/8/8.c"),
            Object(NonMatching, "dlls/engine/9/9.c"),
            Object(NonMatching, "dlls/engine/10_expgfx/expgfx.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/11/11.c", cflags=cflags_dll_noopt_noautoinline, section_alignments={".sdata2": 4}, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/engine/12/12.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/13/13.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/14/14.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/15/15.c", cflags=cflags_dll_noopt_nocse_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/engine/16/16.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/17/17.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/18/18.c"),
            Object(NonMatching, "dlls/engine/19/19.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/20_Hcurves/Hcurves.c"),
            Object(NonMatching, "dlls/engine/20_Hcurves/Hcurves_romcurve.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(NonMatching, "dlls/engine/21/21.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/22/22.c", cflags=cflags_dll_noopt_noautoinline_level3),
            Object(NonMatching, "dlls/engine/23/23.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(NonMatching, "dlls/engine/24/24.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/25/25.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/26/26.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/27/27.c"),
            Object(NonMatching, "dlls/engine/28/28.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/29/29.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/30/30.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/31/31.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/32/32.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/33/33.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/34/34.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/35/35.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/36/36.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/37/37.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/38/38.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/39/39.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/40/40.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/41/41.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/42/42.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/43/43.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/44/44.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/45/45.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/46/46.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/47/47.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/48/48.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/49/49.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/50/50.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(MatchingFor("GSAE01"), "dlls/engine/51/51.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/52_n_attractmode/n_attractmode.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/53/53.c", cflags=cflags_dll_noopt_noinline, section_alignments={".data": 4}),
            Object(MatchingFor("GSAE01"), "dlls/engine/54/54.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/55/55.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/engine/56/56.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/57/57.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/58/58.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/59/59.c"),
            Object(NonMatching, "dlls/engine/60/60.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/engine/61/61.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/62/62.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/63/63.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/64/64.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/65/65.c", extra_cflags=["-inline", "noauto"]),
            Object(NonMatching, "dlls/engine/66/66.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/engine/67/67.c"),
            Object(NonMatching, "dlls/engine/68/68.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/69/69.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/engine/70/70.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(NonMatching, "dlls/engine/71/71.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/engine/72/72.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/engine/73/73.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/engine/74/74.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(MatchingFor("GSAE01"), "dlls/engine/75/75.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/76/76.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/77/77.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "dlls/engine/78/78.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(MatchingFor("GSAE01"), "dlls/engine/79/79.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/80/80.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/81/81.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/82/82.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/engine/83/83.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/engine/84/84.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/85/85.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/86/86.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(MatchingFor("GSAE01"), "dlls/engine/87/87.c"),
            Object(MatchingFor("GSAE01"), "dlls/engine/88/88.c"),

            # dlls/modgfx
            Object(MatchingFor("GSAE01"), "dlls/modgfx/89/89.c"),
            Object(NonMatching, "dlls/modgfx/90/90.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/91/91.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/92/92.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/93/93.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/94/94.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/95/95.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/96/96.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/97/97.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/98/98.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/99/99.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/100/100.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/101/101.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/102/102.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/103/103.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/104/104.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/105/105.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/106/106.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/107/107.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/108/108.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/109/109.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/110/110.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/111/111.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/112/112.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/113/113.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/114/114.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/115/115.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/116/116.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/117/117.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/118/118.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/119/119.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/120/120.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/121/121.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/122/122.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/123/123.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/124/124.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/125/125.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/126/126.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/127/127.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/128/128.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/129/129.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/130/130.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/131/131.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/132/132.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/133/133.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/134/134.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/135/135.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/136/136.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/137/137.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/138/138.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/139/139.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/140/140.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/141/141.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/142/142.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/143/143.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/144/144.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/145/145.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/146/146.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/147/147.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/148/148.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/149/149.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/150/150.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/151/151.c"),
            Object(NonMatching, "dlls/modgfx/152/152.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/153/153.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/154/154.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/155/155.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/156/156.c", extra_cflags=["-opt", "level=3,nopropagation"]),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/157/157.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/158/158.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/159/159.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/160/160.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/161/161.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/162/162.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/163/163.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/164/164.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/165/165.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/166/166.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/167/167.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/168/168.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/169/169.c"),
            Object(MatchingFor("GSAE01"), "dlls/modgfx/170/170.c"),

            # dlls/projgfx
            Object(MatchingFor("GSAE01"), "dlls/projgfx/171/171.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/172/172.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/173/173.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/174/174.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/175/175.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/176/176.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/177/177.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/178/178.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/179/179.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/180/180.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/181/181.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/182/182.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/183/183.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/184/184.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/185/185.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/186/186.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/187/187.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/188/188.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/189/189.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/190/190.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/191/191.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/192/192.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/193/193.c"),
            Object(MatchingFor("GSAE01"), "dlls/projgfx/194/194.c"),

            # dlls/objects
            Object(NonMatching, "dlls/objects/195_Player/player.c", cflags=cflags_dll_noopt_noautoinline),
            # Retail keeps 32-bit mask operations and adjacent dispatch-array offsets unfolded.
            # Deferred emission puts local initializer templates before the function literal pool.
            Object(NonMatching, "dlls/objects/196_Tricky/tricky.c", cflags=cflags_dll_noopt, extra_cflags=["-char signed", "-inline deferred"]),
            Object(MatchingFor("GSAE01"), "dlls/objects/197/197.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/198_AnimatedObj/AnimatedObj.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/199_DIM2RoofRub/DIM2RoofRub.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/objects/200_DepthOfFieldPoint/DepthOfFieldPoint.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/201_Baddie/Baddie.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/battledroid.c"),
            Object(NonMatching, "dlls/objects/202/sharpclaw.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/guardclaw.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/gcrobotpatrol.c", cflags=cflags_dll_noopt_nocse_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/mikaladon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/vambat.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/kooshy.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/weevil.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/pinpon.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/rachnop.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/spittingeba.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/wb.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/mutatedeba.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/hoodedzyck.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/firecrawler.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/hagabon_mk2.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/snowworm.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/baddiewhirlpool.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/202/202.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(Matching, "dlls/objects/203/203.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/204_ChukChuk/ChukChuk.c", cflags=cflags_dll_noopt_noprop_noinline),
            Object(Matching, "dlls/objects/205_IceBall/IceBall.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/206/206.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/207_CannonClaw/CannonClaw.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/208_Grimble/Grimble.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/209_TumbleWeedB/TumbleWeedB.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/211/211.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/212_SkeetlaWall/SkeetlaWall.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/213_Kaldachom/Kaldachom.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/214_KaldachomMe/KaldachomMe.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/215/215.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/216_PinPonSpike/PinPonSpike.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/217_Pollen/Pollen.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/218/218.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/219_MikaBomb/MikaBomb.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/220_MikaBombSha/MikaBombSha.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/221_GCbaddieShi/GCbaddieShi.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/222_baddieInter/baddieInter.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/223_Hagabon/Hagabon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/224_SwarmBaddie/SwarmBaddie.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/225_WispBaddie/WispBaddie.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/226/226.c", mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/227/227.c", section_alignments={".data": 4}),
            Object(MatchingFor("GSAE01"), "dlls/objects/228/228.c", cflags=cflags_dll_noopt_nocse),
            Object(NonMatching, "dlls/objects/229/229.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/230_ReStartMark/ReStartMark.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/231/231.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/232_Checkpoint4/Checkpoint4.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/233_Setuppoint/Setuppoint.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/234_Sideload/Sideload.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/235/235.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/236_InfoPoint/InfoPoint.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/237/237.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/238_EffectBox/EffectBox.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/239/239.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "dlls/objects/240_WarpPoint/WarpPoint.c"),
            Object(NonMatching, "dlls/objects/241_InvHit/InvHit.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/242_iceblast/iceblast.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/243_flameblast/flameblast.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/244/244.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/245_SidekickBal/SidekickBal.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/246_Area/Area.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/247/247.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/248_LevelName/LevelName.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/249/249.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/250_InvisibleHi/InvisibleHi.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/251/251.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/252/252.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/253/253.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/254_MagicPlant/MagicPlant.c", cflags=cflags_dll_noopt_nocse_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/255/255.c", cflags=cflags_dll_noopt_noloopinv),
            Object(MatchingFor("GSAE01"), "dlls/objects/256_TrickyWarp/TrickyWarp.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/257_TrickyGuard/TrickyGuard.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/258_StayPoint/StayPoint.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/259_CurveFish/CurveFish.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/260_SmallBasket/SmallBasket.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/objects/261_LargeCrate/LargeCrate.c"),
            Object(NonMatching, "dlls/objects/262/262.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/263/263.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/264_EndObject/EndObject.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/265/265.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/266_Fall_Ladder/Fall_Ladder.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/267_FireFlyLant/FireFlyLant.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/268_LanternFire/LanternFire.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/269_PortalSpell/PortalSpell.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/270/270.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/271_MMP_Bridge/MMP_Bridge.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/272/272.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/273/273.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/274/274.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/275/275.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/276_IMMultiSeq/IMMultiSeq.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/277/277.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/278_WM_Column/WM_Column.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/279_AppleOnTree/AppleOnTree.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/280_Duster/Duster.c", mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/281_coldWaterCo/coldWaterCo.c"),
            Object(Matching, "dlls/objects/282/282.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/283_Landed_Arwi/Landed_Arwi.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/284/284.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/285/285.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/286_MagicCaveBo/MagicCaveBo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/287_MagicCaveTo/MagicCaveTo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/288_TrickyGuard/TrickyGuard.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/289/289.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/290_CCTestInfot/CCTestInfot.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/291_fuelCell/fuelCell.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/292/292.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/293_curve/curve.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/294/294.c", cflags=cflags_dll_noopt_noloopinv, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/295/295.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/296_KT_Torch/KT_Torch.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/297_CampFire/CampFire.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/298_CFCrate/CFCrate.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/objects/299_FXEmit/FXEmit.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/300_Transporter/Transporter.c", cflags=cflags_dll_noopt_noloopinv),
            Object(MatchingFor("GSAE01"), "dlls/objects/301_LFXEmitter/LFXEmitter.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/302/302.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/303_BarrelPad/BarrelPad.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/304_AreaFXEmit/AreaFXEmit.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/305/305.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/306_WaterFallSp/WaterFallSp.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/307_sfxPlayer/sfxPlayer.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/308_texscroll2/texscroll2.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/309_texscroll/texscroll.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/310_WaveAnimato/WaveAnimato.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/311_AlphaAnimat/AlphaAnimat.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/312_GroundAnima/GroundAnima.c"),
            Object(Matching, "dlls/objects/313_HitAnimator/HitAnimator.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/314_VisAnimator/VisAnimator.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/315_WallAnimato/WallAnimato.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/316_XYZAnimator/XYZAnimator.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/317_ExplodeAnim/ExplodeAnim.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/318/318.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/319_TexFrameAni/TexFrameAni.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/320_fogControl/fogControl.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/321_Lightning/Lightning.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/322_FElevContro/FElevContro.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/323_FEseqobject/FEseqobject.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/324/324.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/325_CloudPrison/CloudPrison.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/326_CloudShipCo/CloudShipCo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/327/327.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/328_CFGuardian/CFGuardian.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/329/329.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/330_CFPowerBase/CFPowerBase.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/331_CFMainCryst/CFMainCryst.c"),
            Object(NonMatching, "dlls/objects/332/332.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/333_LaserBeam/LaserBeam.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/334_CFPrisonGua/CFPrisonGua.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/335_CFPrisonUnc/CFPrisonUnc.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/336_GCRobotLigh/GCRobotLigh.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/337_CFScalesGal/CFScalesGal.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/338_CF_ObjCreat/CF_ObjCreat.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/339_CFPerch/CFPerch.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/340/340.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/341/341.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/342/342.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/343_SpiritDoorS/SpiritDoorS.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/344/344.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/345/345.c", cflags=cflags_dll_noopt_noloopinv_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/346/346.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/347_CFForceFiel/CFForceFiel.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/348_CFForceFiel/CFForceFiel.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/349/349.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/350/350.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/351/351.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/352/352.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/353_CFTreasRobo/CFTreasRobo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/354_CFMagicWall/CFMagicWall.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/355/355.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/356_CFLevelCont/CFLevelCont.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/357_CFRemovalSh/CFRemovalSh.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/358/358.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/359_SpiritDoorL/SpiritDoorL.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/360_HoloPoint/HoloPoint.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/361_IMIceMounta/IMIceMounta.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/362_CRrockfall/CRrockfall.c", cflags=cflags_dll_noopt_noprop_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/363/363.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/364/364.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/365_IMIcePillar/IMIcePillar.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/366_IMAnimSpace/IMAnimSpace.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/367_IMSpaceThru/IMSpaceThru.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/368_IMSpaceRing/IMSpaceRing.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/369_IMSpaceRing/IMSpaceRing.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/370_LINKB_levco/LINKB_levco.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/371_LINK_levcon/LINK_levcon.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/372_CCriverflow/CCriverflow.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/373_DFropenode/DFropenode.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/374_DFSH_Door1S/DFSH_Door1S.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/375/375.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/376_DFSH_Shrine/DFSH_Shrine.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/377_DFSH_ObjCre/DFSH_ObjCre.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/378_SpiritPrize/SpiritPrize.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/379_DFSH_LaserB/DFSH_LaserB.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/380_GCRobotPatr/GCRobotPatr.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/381/381.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/382_MMP_levelco/MMP_levelco.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/383/383.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/384_MMP_asteroi/MMP_asteroi.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/385_MMP_trenchF/MMP_trenchF.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/386_MMP_moonroc/MMP_moonroc.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/387_MMP_gyserve/MMP_gyserve.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/388/388.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/389_CCgasvent/CCgasvent.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/390_CCgasventCo/CCgasventCo.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/391_CCqueen/CCqueen.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/392_CClightfoot/CClightfoot.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/393_CCSharpclaw/CCSharpclaw.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/394_CCpedstal/CCpedstal.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/395_CClevcontro/CClevcontro.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/396_MMSH_Shrine/MMSH_Shrine.c", cflags=cflags_dll_noopt_nolifetimes_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/397_MMSH_Scales/MMSH_Scales.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/398_MMSH_WaterS/MMSH_WaterS.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/399_ECSH_Shrine/ECSH_Shrine.c", cflags=cflags_dll_noopt_nostrength),
            Object(MatchingFor("GSAE01"), "dlls/objects/400_ECSH_Cup/ECSH_Cup.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/401_ECSH_Creato/ECSH_Creato.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/402_GPSH_Shrine/GPSH_Shrine.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/403_GPSH_ObjCre/GPSH_ObjCre.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/404_GPSH_Scene/GPSH_Scene.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/405_DBSH_Shrine/DBSH_Shrine.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/406_DBSH_Symbol/DBSH_Symbol.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/407/407.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/408_NWSH_levcon/NWSH_levcon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/409/409.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/410/410.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/411/411.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/412/412.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/413/413.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/414/414.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/415_NW_treebrid/NW_treebrid.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/416_NW_geyser/NW_geyser.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/417/417.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/418_NW_tricky/NW_tricky.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/419/419.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/420/420.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/421_NW_levcontr/NW_levcontr.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/422_SH_tricky/SH_tricky.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/423/423.c", cflags=cflags_dll_noopt_noloopinv_nolifetimes_nodead),
            Object(MatchingFor("GSAE01"), "dlls/objects/424_SH_killermu/SH_killermu.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/425_BombPlant/BombPlant.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/426_BombPlantSp/BombPlantSp.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/427_BombPlantin/BombPlantin.c"),
            Object(Matching, "dlls/objects/428_SH_queenear/SH_queenear.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/429_SH_thorntai/SHthorntail.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/430_SH_LevelCon/SH_LevelCon.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/431_SH_swaplift/SH_swaplift.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/432_SH_swapston/SH_swapston.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/433_SH_staff/SH_staff.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/434_SH_staffHaz/SH_staffHaz.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/435_SH_Beacon/SH_Beacon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/436_SH_EmptyTum/SH_EmptyTum.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/437/437.c", cflags=[*cflags_dll_noopt, "-inline", "noauto"]),
            Object(MatchingFor("GSAE01"), "dlls/objects/438_SC_levelcon/SC_levelcon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/439/439.c", cflags=cflags_dll_noopt_nocse_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/440_SC_totempol/SC_totempol.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/441_SC_Cloudrun/SC_Cloudrun.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/442_SC_totempuz/SC_totempuz.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/443_SC_totembon/SC_totembon.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/444_SC_totemstr/SC_totemstr.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/445/445.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/446/446.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/447_DIMLavaBall/DIMLavaBall.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/448_DIMLogFire/DIMLogFire.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/449_DIMSnowBall/DIMSnowBall.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/450_DIMSnowBall/DIMSnowBall.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/451_DIMGate/DIMGate.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/452_DIMIceWall/DIMIceWall.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/453_DIMBarrier/DIMBarrier.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/454_DIMCannon/DIMCannon.c"),
            Object(NonMatching, "dlls/objects/455_DIMLavaSmas/DIMLavaSmas.c", cflags=cflags_dll_noopt_noprop_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/456_DIMBridgeCo/DIMBridgeCo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/457_DIMDismount/DIMDismount.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/458_DIMExplosio/DIMExplosio.c", cflags=cflags_dll_noopt_noinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/459_DIMWoodDoor/DIMWoodDoor.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/460_DIMMagicBri/DIMMagicBri.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/461_DIM_LevelCo/DIM_LevelCo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/462/462.c", cflags=cflags_dll_noopt_nostrength),
            Object(MatchingFor("GSAE01"), "dlls/objects/463/463.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/464_DIM_tricky/DIM_tricky.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/465_DIMTruthHor/DIMTruthHor.c"),
            Object(NonMatching, "dlls/objects/466_WORLDplanet/WORLDplanet.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/467/467.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/468_WORLDAstero/WORLDAstero.c", mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/469_DIM2Conveyo/DIM2Conveyo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/470/470.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/objects/471_DIM2SnowBal/DIM2SnowBal.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/472_DIM2PathGen/DIM2PathGen.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/473_DIM2PrisonM/DIM2PrisonM.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/474/474.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/475/475.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/476_DIM2IceFloe/DIM2IceFloe.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/477_DIM2Icicle/DIM2Icicle.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/478_DIM2LavaCon/DIM2LavaCon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/479/479.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/480_DIM_Boss/DIM_Boss.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/481_DIM_BossGut/DIM_BossGut.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/482_DIM_BossTon/DIM_BossTon.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/objects/483_DIM_BossGut/DIM_BossGut.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/484_MAGICMaker/MAGICMaker.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/485_DIM_BossSpi/DIM_BossSpi.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/486_DIMbosscrac/DIMbosscrac.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/487_DIMbossfire/DIMbossfire.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/488_SB_Galleon/SB_Galleon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/489_SB_Propelle/SB_Propelle.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/490_SB_ShipHead/SB_ShipHead.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/491_SB_ShipMast/SB_ShipMast.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/492_SB_ShipGun/SB_ShipGun.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/493_SB_FireBall/SB_FireBall.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/494_SB_CannonBa/SB_CannonBa.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/495_SB_CloudBal/SB_CloudBal.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/496_SB_KyteCage/SB_KyteCage.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/497_SB_SeqDoor/SB_SeqDoor.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/498_SB_CageKyte/SB_CageKyte.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/499_SB_MiniFire/SB_MiniFire.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/500/500.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/501/501.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/502/502.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/503_SB_ShipGunB/SB_ShipGunB.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/504_WM_Galleon/WM_Galleon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/505_WM_ObjCreat/WM_ObjCreat.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/506_WM_seqobjec/WM_seqobjec.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/507/507.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/508/508.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/509_WM_LaserTar/WM_LaserTar.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/510/510.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/511/511.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/512/512.c", cflags=cflags_dll_noopt_nostrength_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/513_WM_colrise/WM_colrise.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/514/514.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/515/515.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/516_WM_Torch/WM_Torch.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/517_WM_Vein/WM_Vein.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/518_LightSource/LightSource.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/519_WM_Worm/WM_Worm.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/objects/520_WM_Wallpowe/WM_Wallpowe.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/521_WM_LevelCon/WM_LevelCon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/522_WM_GeneralS/WM_GeneralS.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/523_FireFly/FireFly.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/524_WM_spiritpl/WM_spiritpl.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/525_WM_seqpoint/WM_seqpoint.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/526_WM_sun/WM_sun.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/527_WM_SpiritSe/WM_SpiritSe.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/528_WM_Planets/WM_Planets.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/529/529.c", cflags=cflags_dll_noopt_nodead_noloopinv_noautoinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/530/530.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/531_WM_VConsole/WM_VConsole.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/532_WM_TransTop/WM_TransTop.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/533_WM_newcryst/WM_newcryst.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/534_VFP_LevelCo/VFP_LevelCo.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/535_VFP_ObjCrea/VFP_ObjCrea.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/536_VFP_MiniFir/VFP_MiniFir.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/537/537.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/538_VFP_statueb/VFP_statueb.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/539/539.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/540_VFP_Ladders/VFP_Ladders.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/541/541.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/542_VFP_Block1/VFP_Block1.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/543/543.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/544/544.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/545/545.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/546_VFPDragHead/VFPDragHead.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/547_VFP_corepla/VFP_corepla.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/548/548.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/549_VFP_flamepo/VFP_flamepo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/550_VFP_lavapoo/VFP_lavapoo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/551_VFP_lavasta/VFP_lavasta.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/552/552.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/553_DFP_LevelCo/DFP_LevelCo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/554_DFP_ObjCrea/DFP_ObjCrea.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/555_DFP_Torch/DFP_Torch.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/objects/556/556.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/557_DFP_seqpoin/DFP_seqpoin.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/558/558.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/559_DFP_floorba/DFP_floorba.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/560_DFP_wallbar/DFP_wallbar.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/561_DFP_ForceAw/DFP_ForceAw.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/562_DFP_RotateP/DFP_RotateP.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/563_DFP_Statue1/DFP_Statue1.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/564_DFP_PerchSw/DFP_PerchSw.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/565_DFP_TargetB/DFP_TargetB.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/566_DFP_LaserBe/laser.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/567_DFPSpPl/DFPSpPl.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/568_LINKA_levco/LINKA_levco.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/569/textblock.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/570_DFP_Platfor/DFP_Platfor.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/571_DFP_Lightni/DFP_Lightni.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/572_DFP_PowerSl/DFP_PowerSl.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/573_DBPointMum/DBPointMum.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/574/574.c"),
            Object(Matching, "dlls/objects/575_DB_egg/DB_egg.c", cflags=cflags_dll_noopt_noloopinv),
            Object(MatchingFor("GSAE01"), "dlls/objects/576_GCRobotBlas/GCRobotBlas.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/577_DrakorEnerg/DrakorEnerg.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/578_DBstealerwo/DBstealerwo.c", cflags=cflags_dll_noopt_noloopinv, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/579_DBHoleContr/DBHoleContr.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/580/580.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/581/581.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/582/582.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/583/583.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/584/584.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/585/585.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/586/586.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/587/587.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/588_BossDrakor_/BossDrakor_.c"),
            Object(NonMatching, "dlls/objects/589_BossDrakor/BossDrakor.c", cflags=cflags_dll_noopt_nocse_noprop_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/590/590.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/objects/591_KT_RexLevel/KT_RexLevel.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/592_KT_Rex/KT_Rex.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/593_KT_RexFloor/KT_RexFloor.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/594_KT_Lazerwal/KT_Lazerwal.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/595_KT_Lazerlig/KT_Lazerlig.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/596_KT_Fallingr/KT_Fallingr.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/597/597.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/598_DIMSnowHorn/DIMSnowHorn.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/599_DR_EarthWar/DR_EarthWar.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/600_DR_CloudRun/DR_CloudRun.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/601_SB_Cloudrun/SB_Cloudrun.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/602_StaticCamer/StaticCamer.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/603_MSPlantingS/MSPlantingS.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/604/604.c", cflags=cflags_dll_noopt_noloopinv_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/605_CRCloudRace/CRCloudRace.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/606/606.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/607_CRFuelTank/CRFuelTank.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/608/608.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/609_DR_LaserCan/DR_LaserCan.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/610/610.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/611_GM_MazeWell/GM_MazeWell.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/612/612.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/613_DR_Creator/DR_Creator.c"),
            Object(Matching, "dlls/objects/614_KytesMum/KytesMum.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/615/615.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/616_DR_CageCont/DR_CageCont.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/617_ExplodePlan/ExplodePlan.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/618_DR_Geezer/DR_Geezer.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/619_DR_Chimmey/DR_Chimmey.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/620/620.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/621_DR_Vines/DR_Vines.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/622/622.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/623/623.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/624_DR_Rock/DR_Rock.c"),
            Object(NonMatching, "dlls/objects/625/625.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(Matching, "dlls/objects/626/626.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(Matching, "dlls/objects/627_FirePipe/FirePipe.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/628_DR_pulley/DR_pulley.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/629_DR_cradle/DR_cradle.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/630/630.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/631_CFWindLiftL/CFWindLiftL.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/632/632.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/633_DR_EnergyDi/DR_EnergyDi.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/634_DR_Collapse/DR_Collapse.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/635/635.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/636_DR_LightBea/DR_LightBea.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/637/637.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/638_DRMusicCont/DRMusicCont.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/639/639.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/640_DR_CloudPer/DR_CloudPer.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/641_DR_EarthCal/DR_EarthCal.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/642_BarrelGener/BarrelGener.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/643_DR_BarrelGr/DR_BarrelGr.c", mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/644/644.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/645_SPShop/SPShop.c"),
            Object(Matching, "dlls/objects/646_SPShopKeepe/SPShopKeepe.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/647_SPScarab/SPScarab.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/648_SPDrape/SPDrape.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/649_SPitembeam/SPitembeam.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/650/650.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/651/651.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(MatchingFor("GSAE01"), "dlls/objects/652_WCBouncyCra/WCBouncyCra.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/653_WCLevelCont/WCLevelCont.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/654_WCBeacon/WCBeacon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/655_WCPressureS/WCPressureS.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/656_WCPushBlock/WCPushBlock.c", cflags=[*cflags_base, "-opt", "nopeephole,noschedule,nocse,nodeadstore"]),
            Object(MatchingFor("GSAE01"), "dlls/objects/657_WCTile/WCTile.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/objects/658_WCTrexStatu/WCTrexStatu.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/659/659.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/660/660.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/661_WCApertureS/WCApertureS.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/662_WCTempleDia/WCTempleDia.c", cflags=cflags_dll_noopt_noinline, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/663_WCTempleBri/WCTempleBri.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(MatchingFor("GSAE01"), "dlls/objects/664_WCFloorTile/WCFloorTile.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/665/665.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/666_ARWArwing/ARWArwing.c", cflags=cflags_dll_noopt_noprop_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/667/667.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/668_ARWArwingBo/ARWArwingBo.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/669_ARWArwingGu/ARWArwingGu.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/670/670.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/671_ARWBombColl/ARWBombColl.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/672/672.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/673_ARWLevelCon/ARWLevelCon.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/674_ARWSpeedStr/ARWSpeedStr.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/675/675.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/676/676.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/677_ARWGenerato/ARWGenerato.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/678_ARWSquadron/ARWSquadron.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/679_ARWProximit/ARWProximit.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/objects/680_ARWBlocker/ARWBlocker.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/681/681.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/682_LGTDirectio/LGTDirectio.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/683_LGTProjecte/LGTProjecte.c", cflags=cflags_dll_noopt_nocse),
            Object(MatchingFor("GSAE01"), "dlls/objects/684_LGTControlL/LGTControlL.c", cflags=cflags_dll_noopt_level1),
            Object(MatchingFor("GSAE01"), "dlls/objects/685/685.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/686_WaterFlowWe/WaterFlowWe.c", extra_cflags=["-opt", "nodeadstore"]),
            Object(MatchingFor("GSAE01"), "dlls/objects/687/687.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/688_BrokenPipe/BrokenPipe.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/689_CmbSrc/CmbSrc.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/690_DustMoteSou/DustMoteSou.c"),
            Object(NonMatching, "dlls/objects/691/691.c", cflags=cflags_dll_noopt_noprop),
            Object(MatchingFor("GSAE01"), "dlls/objects/692_CNTcounter/CNTcounter.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/693_Timer/Timer.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/694_CNThitObjec/CNThitObjec.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/695_MCUpgrade/MCUpgrade.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/696_MCUpgradeMa/MCUpgradeMa.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/697_MCStaffEffe/MCStaffEffe.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/698_MCLightning/MCLightning.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/699_GF_LevelCon/GF_LevelCon.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/700_Andross/Andross.c", cflags=cflags_dll_noopt_noautoinline_alwaysinline),
            Object(NonMatching, "dlls/objects/701/701.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "dlls/objects/702_AndrossBrai/AndrossBrai.c"),
            Object(MatchingFor("GSAE01"), "dlls/objects/703_AndrossLigh/AndrossLigh.c"),
            Object(NonMatching, "dlls/objects/704/704.c"),

            # main
            Object(NonMatching, "main/render.c"),
            Object(Matching, "main/audio.c", cflags=cflags_dll_noopt_nostrength_noautoinline),
            Object(MatchingFor("GSAE01"), "main/audio_sfx.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "main/audio_stream.c"),
            Object(MatchingFor("GSAE01"), "main/camera.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/curves.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "main/voxmaps.c"),
            Object(Matching, "main/modelEngine.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "main/pad.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "main/fileio.c", cflags=cflags_dll_noopt_noloopinv_noautoinline),
            Object(NonMatching, "main/gametext.c", cflags=cflags_dll_noopt_nolifetimes_noinline),
            Object(MatchingFor("GSAE01"), "main/gametext_measurebyid.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(NonMatching, "main/gametext_tail.c"),
            Object(NonMatching, "main/textrender.c"),
            Object(MatchingFor("GSAE01"), "main/textrender_gettext.c", cflags=cflags_dll_noopt_noprop),
            Object(NonMatching, "main/textrender_run.c"),
            Object(NonMatching, "main/subtitle.c", cflags=cflags_dll_noopt_level1),
            Object(Matching, "main/textrender_drawbox.c"),
            Object(NonMatching, "main/textrender_boxtex.c", cflags=cflags_dll_noopt_nocse_nolifetimes_noloopinv_noprop_nostrength),
            Object(MatchingFor("GSAE01"), "main/modellight.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "main/gameloop.c", cflags=[*cflags_dll_noopt, "-inline", "noauto"]),
            Object(NonMatching, "main/gameloop_buttonobj.c", cflags=[*cflags_dll_nosched, "-inline", "noauto"]),
            Object(MatchingFor("GSAE01"), "main/gameloop_main.c", cflags=[*cflags_dll_noopt, "-inline", "noauto"]),
            Object(NonMatching, "main/vecmath.c", cflags=cflags_dll_noopt_nostrength),
            Object(MatchingFor("GSAE01"), "main/vecmath_vec3.c"),
            Object(NonMatching, "main/mm.c", cflags=[*cflags_dll_noopt, "-inline", "noauto"]),
            Object(NonMatching, "main/model.c", cflags=[*cflags_dll_noopt_noloopinv, "-inline", "noauto"]),
            Object(NonMatching, "main/object.c"),
            Object(MatchingFor("GSAE01"), "main/skystars.c"),
            Object(NonMatching, "main/objanim.c", cflags=cflags_dll_noopt_nocse),
            Object(NonMatching, "main/lightmap.c", cflags=[*cflags_dll_noopt_noprop, "-inline", "noauto"]),
            Object(MatchingFor("GSAE01"), "main/lightmap_initmapblocks.c", cflags=[*cflags_dll_noopt_nocse_noprop, "-inline", "noauto"]),
            Object(NonMatching, "main/lightmap_draw.c", cflags=cflags_dll_noopt_noautoinline, section_alignments={".data": 4}),
            Object(NonMatching, "main/objhits.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/objlib.c"),
            Object(NonMatching, "main/objprint.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "main/objprint_dolphin.c", cflags=[*cflags_dll_noopt_noloopinv_nolifetimes_zerodata, "-inline", "noauto"], mw_version="GC/2.0"),
            Object(NonMatching, "main/pi_dolphin.c", cflags=[*cflags_dll_noopt_noloopinv_zerodata, "-inline", "noauto"]),
            Object(NonMatching, "main/pi_videoinit.c", cflags=[*cflags_dll_noopt_nocse_noloopinv_nolifetimes_noprop_zerodata, "-inline", "noauto"]),
            Object(MatchingFor("GSAE01"), "main/pi_pathsearch.c", cflags=[*cflags_dll_noopt_noloopinv_zerodata, "-inline", "noauto"]),
            Object(NonMatching, "main/zlb.c", cflags=cflags_base, **zlb_object_kwargs),
            Object(Matching, "main/shader_dolphin.c"),
            Object(MatchingFor("GSAE01"), "main/boot_logo.c"),
            Object(NonMatching, "main/rcp_dolphin.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "main/texture.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "main/shader.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "main/tex_dolphin.c", cflags=cflags_dll_noopt_noautoinline, section_alignments={".data": 4}, mw_version="GC/2.0"),
            Object(NonMatching, "main/shadow_dolphin.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "main/track_dolphin.c", cflags=cflags_dll_noopt_noautoinline, mw_version="GC/2.0"),
            Object(NonMatching, "main/newshadows.c", cflags=cflags_dll_noopt_nodead_noautoinline),
            Object(MatchingFor("GSAE01"), "track/intersect.c", cflags=cflags_dll_noopt_nocse_noautoinline, section_alignments={".data": 4}),
            Object(MatchingFor("GSAE01"), "track/intersect_screenmath.c", cflags=cflags_dll_noopt_noautoinline),
            Object(MatchingFor("GSAE01"), "track/intersect_mtx44.c", cflags=cflags_dll_noopt_noautoinline),
            Object(NonMatching, "track/intersect_render.c", cflags=cflags_dll_noopt, mw_version="GC/2.0"),
            Object(Matching, "track/intersect_memcard.c", cflags=cflags_dll_noopt_noautoinline),

            # main/thp
            Object(Matching, "main/thp/dll_3b.c", cflags=cflags_dll_noopt_noinline),
            Object(MatchingFor("GSAE01"), "main/thp/n_options.c"),
            Object(MatchingFor("GSAE01"), "main/thp/dll_3e.c", section_alignments={".sbss": 4}),
            Object(MatchingFor("GSAE01"), "main/thp/attractmovie.c"),
            Object(MatchingFor("GSAE01"), "main/thp/picmenu.c", cflags=cflags_dll_noopt_noinline, section_alignments={".sdata2": 4}),
            Object(MatchingFor("GSAE01"), "main/thp/THPRead.c"),
            Object(MatchingFor("GSAE01"), "main/thp/THPVideoDecode.c"),
            Object(NonMatching, "main/dll_80136a40.c", cflags=cflags_dll_noopt_nostrength),
            Object(MatchingFor("GSAE01"), "main/obj_movelib.c", cflags=cflags_dll_noopt_nocse),

            # MSL-derived game math
            Object(MatchingFor("GSAE01"), "main/rand.c", cflags=cflags_game, extra_cflags=["-O0"], progress_category="game"),
            Object(MatchingFor("GSAE01"), "main/math_80292d3c.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "main/trig_float_helpers.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "functions,peephole", "-inline", "auto", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "main/math_8029312c.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "main/acosf.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole,functions", "-inline", "auto", "-sym", "on", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "main/trig.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "functions,peephole", "-inline", "auto", "-sym", "on", *msl_math_extra], progress_category="game"),
            Object(MatchingFor("GSAE01"), "main/sincosf.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "functions,peephole", "-inline", "auto", "-sym", "on", *msl_math_extra], progress_category="game"),
        ],
    },
]


# Optional callback to adjust link order. This can be used to add, remove, or reorder objects.
# This is called once per module, with the module ID and the current link order.
#
# For example, this adds "dummy.c" to the end of the DOL link order if configured with --non-matching.
# "dummy.c" *must* be configured as a Matching (or Equivalent) object in order to be linked.
def link_order_callback(module_id: int, objects: List[str]) -> List[str]:
    # Don't modify the link order for matching builds
    if not config.non_matching:
        return objects
    if module_id == 0:  # DOL
        return objects + ["dummy.c"]
    return objects


# Uncomment to enable the link order callback.
# config.link_order_callback = link_order_callback


# Optional extra categories for progress tracking
# Adjust as desired for your project
config.progress_categories = [
    ProgressCategory("game", "Game Code"),
    ProgressCategory("sdk", "SDK Code"),
    ProgressCategory("third_party", "Third-Party Code"),
]
config.progress_each_module = args.verbose
# Optional extra arguments to `objdiff-cli report generate`
config.progress_report_args = [
    # Marks relocations as mismatching if the target value is different
    # Default is "functionRelocDiffs=none", which is most lenient
    # "--config functionRelocDiffs=data_value",
]

if args.mode == "configure":
    # Write build.ninja and objdiff.json
    generate_build(config)
elif args.mode == "progress":
    # Print progress information
    calculate_progress(config)
else:
    sys.exit("Unknown mode: " + args.mode)
