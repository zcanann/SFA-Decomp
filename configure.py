#!/usr/bin/env python3


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

Object = ProjectObject

DEFAULT_VERSION = 0
VERSIONS = [
    "GSAE01",
    "GSAJ01",
    "GSAP01",
    "GSAE01_rev1",
    "GSAP01_rev1",
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
    "--joint-matrices-nocfa",
    action="store_true",
    help="experimental EN joint-matrix function bounds (run tools/dtk_nocfa.py first)",
)
parser.set_defaults(non_matching=True)
args = parser.parse_args()

config = ProjectConfig()
config.version = str(args.version)
version_num = VERSIONS.index(config.version)

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
config.progress_requires_link = config.version == "GSAE01" or not config.non_matching
if not is_windows():
    config.wrapper = args.wrapper
if not config.non_matching:
    config.asm_dir = None

config.binutils_tag = "2.42-1"
config.compilers_tag = "20251118"
config.dtk_tag = "v1.8.0"
config.objdiff_tag = "v3.5.1"
config.sjiswrap_tag = "v1.2.2"
config.wibo_tag = "1.1.0"

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
    config.ldflags.append("-g")
if args.map:
    config.ldflags.append("-mapunused")

config.reconfig_deps = []
config.split_deps = [
    Path("config") / config.version / "splits.txt",
    Path("config") / config.version / "symbols.txt",
]
if args.joint_matrices_nocfa:
    from tools.dtk_nocfa import PATCH, binary_path, write_overlay

    if config.version != "GSAE01" or args.dtk is not None:
        sys.exit("--joint-matrices-nocfa requires GSAE01 and supplies its own patched DTK")
    config.dtk_path = binary_path(config.build_dir)
    if not config.dtk_path.is_file():
        sys.exit("Build the prototype first: python3 tools/dtk_nocfa.py --test")
    canonical_config = config.config_path
    config.config_path, overlay_symbols = write_overlay(config.build_dir)
    config.reconfig_deps.extend([
        Path("tools/dtk_nocfa.py"), PATCH, canonical_config,
        Path("config/GSAE01/symbols.txt"),
    ])
    config.split_deps.append(overlay_symbols)
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

config.scratch_preset_id = None

cflags_base = [
    "-nodefaults",
    "-proc gekko",
    "-align powerpc",
    "-enum int",
    "-fp hardware",
    "-Cpp_exceptions off",
    "-O4,p",
    "-inline auto",
    '-pragma "cats off"',
    '-pragma "warn_notinlined off"',
    "-maxerrors 1",
    "-nosyspath",
    "-RTTI off",
    "-fp_contract on",
    "-str reuse",
    "-multibyte",
    "-i include",
    f"-i build/{config.version}/include",
    f"-DBUILD_VERSION={version_num}",
    f"-DVERSION_{config.version}",
]

if args.debug:
    cflags_base.extend(["-sym on", "-DDEBUG=1"])
else:
    cflags_base.append("-DNDEBUG=1")

if args.warn == "all":
    cflags_base.append("-W all")
elif args.warn == "off":
    cflags_base.append("-W off")
elif args.warn == "error":
    cflags_base.append("-W error")

cflags_runtime = [
    *cflags_base,
    "-char signed",
    "-use_lmw_stmw on",
    "-str reuse,pool,readonly",
    "-gccinc",
    "-common off",
    "-inline auto",
]

cflags_runtime_125 = [flag for flag in cflags_runtime if flag != "-gccinc"]

cflags_game = [*cflags_base, "-char signed"]

cflags_dll_noopt = [
    *cflags_game,
    "-opt", "nopeephole,noschedule",
]

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

cflags_dll_noopt_noautoinline_deferred = [
    *cflags_game,
    "-opt", "nopeephole,noschedule",
    "-inline", "noauto,deferred",
]

cflags_dll_noopt_nocse = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse",
]

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

cflags_dll_noopt_nocse_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse",
    "-inline", "off",
]

cflags_dll_noopt_noprop = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation",
]

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

cflags_dll_noopt_nocse_noprop = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nocse,nopropagation",
]

cflags_dll_noopt_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule",
    "-inline", "off",
]

cflags_dll_noopt_noprop_noinline = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nopropagation",
    "-inline", "off",
]

cflags_dll_noopt_nodead = [
    *cflags_game,
    "-opt", "nopeephole,noschedule,nodead",
]

cflags_msl = [
    *cflags_base,
    "-char signed",
    "-use_lmw_stmw on",
    "-str reuse,pool,readonly",
]

msl_math_extra = ["-schedule", "off"]
msl_math_o0_cflags = [flag for flag in cflags_base if flag != "-O4,p"]

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

config.compiler_version = "GC/1.3"
config.linker_version = "GC/1.3.2"


def DolphinLib(lib_name: str, objects: List[Object]) -> Dict[str, Any]:
    return {
        "lib": lib_name,
        "mw_version": "GC/1.2.5n",
        "cflags": cflags_base,
        "progress_category": "sdk",
        "objects": objects,
    }


def MSLLib(lib_name: str, objects: List[Object]) -> Dict[str, Any]:
    # MSL has its own library profile, independent of Dolphin and game code.
    # Keep the established per-unit compiler/flag overrides below: the active
    # library units already match. cflags_msl is only for units that need it.
    return {
        "lib": lib_name,
        "mw_version": "GC/1.2.5n",
        "cflags": cflags_base,
        "progress_category": "third_party",
        "objects": objects,
    }


def Rel(lib_name: str, objects: List[Object]) -> Dict[str, Any]:
    return {
        "lib": lib_name,
        "cflags": cflags_rel,
        "progress_category": "game",
        "objects": objects,
    }


# All active source units are verified across the five supported retail versions.
Matching = True


def Object(completed, name, **options):
    """Apply generated cross-version exactness without duplicating every call."""

    return ProjectObject(completed or name in matching_units, name, **options)


config.warn_missing_config = True
config.warn_missing_source = False
config.libs = [
    {
        "lib": "Runtime.PPCEABI.H",
        "mw_version": "GC/1.3.2",
        "cflags": cflags_runtime,
        "progress_category": "sdk",
        "objects": [
            Object(Matching, "Runtime.PPCEABI.H/__start.c", mw_version="GC/1.2.5n", cflags=cflags_runtime_125),
            Object(Matching, "Runtime.PPCEABI.H/__mem.c", mw_version="GC/1.3"),
            Object(Matching, "Runtime.PPCEABI.H/mem_TRK.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/__exception.s"),
            Object(Matching, "Runtime.PPCEABI.H/__va_arg.c"),
            Object(Matching, "Runtime.PPCEABI.H/global_destructor_chain.c"),
            Object(Matching, "Runtime.PPCEABI.H/runtime.c"),
            Object(Matching, "Runtime.PPCEABI.H/__init_cpp_exceptions.cpp"),
            Object(Matching, "Runtime.PPCEABI.H/fragment.c"),
            Object(Matching, "Runtime.PPCEABI.H/GCN_mem_alloc.c"),
        ],
    },
    DolphinLib(
        "os",
        [
            Object(Matching, "dolphin/os/OS.c"),
            Object(Matching, "dolphin/os/OSAlarm.c"),
            Object(Matching, "dolphin/os/OSAlloc.c"),
            Object(Matching, "dolphin/os/OSArena.c"),
            Object(Matching, "dolphin/os/OSAudioSystem.c"),
            Object(Matching, "dolphin/os/OSCache.c"),
            Object(Matching, "dolphin/os/OSContext.c"),
            Object(Matching, "dolphin/os/OSError.c"),
            Object(Matching, "dolphin/os/OSExec.c"),
            Object(Matching, "dolphin/os/OSFont.c"),
            Object(Matching, "dolphin/os/OSInterrupt.c"),
            Object(Matching, "dolphin/os/OSLink.c"),
            Object(Matching, "dolphin/os/OSMessage.c"),
            Object(Matching, "dolphin/os/OSMemory.c"),
            Object(Matching, "dolphin/os/OSMutex.c"),
            Object(Matching, "dolphin/os/OSReboot.c"),
            Object(Matching, "dolphin/os/OSReset.c"),
            Object(Matching, "dolphin/os/OSResetSW.c"),
            Object(Matching, "dolphin/os/OSRtc.c"),
            Object(Matching, "dolphin/os/OSStopwatch.c"),
            Object(Matching, "dolphin/os/OSSync.c"),
            Object(Matching, "dolphin/os/OSThread.c"),
            Object(Matching, "dolphin/os/OSTime.c"),
            Object(Matching, "dolphin/os/__ppc_eabi_init.c"),
        ],
    ),
    DolphinLib(
        "base",
        [
            Object(Matching, "dolphin/base/PPCArch.c"),
        ],
    ),
    DolphinLib(
        "db",
        [
            Object(Matching, "dolphin/db/db.c"),
        ],
    ),
    DolphinLib(
        "mtx",
        [
            Object(Matching, "dolphin/mtx/mtx.c", source="dolphin/mtx/mtx.c", mw_version="GC/1.2.5", extra_cflags=["-DGEKKO", "-fp_contract", "off"]),
            Object(Matching, "dolphin/mtx/mtxvec.c", source="dolphin/mtx/mtxvec.c"),
            # Unpatched SDK lineage: C_VECReflect arithmetic and epilogue match MP4's profile.
            Object(Matching, "dolphin/mtx/vec.c", mw_version="GC/1.2.5", extra_cflags=["-fp_contract", "off"]),
            Object(Matching, "dolphin/mtx/mtx44.c"),
            Object(Matching, "dolphin/mtx/psmtx.c"),
        ],
    ),
    DolphinLib(
        "dvd",
        [
            Object(Matching, "dolphin/dvd/dvdlow.c"),
            Object(Matching, "dolphin/dvd/dvdfs.c"),
            Object(Matching, "dolphin/dvd/dvd.c"),
            Object(Matching, "dolphin/dvd/dvdqueue.c"),
            Object(Matching, "dolphin/dvd/dvderror.c"),
            Object(Matching, "dolphin/dvd/fstload.c"),
            Object(Matching, "dolphin/dvd/dvdFatal.c"),
        ],
    ),
    DolphinLib(
        "ai",
        [
            Object(Matching, "dolphin/ai/ai.c"),
        ],
    ),
    DolphinLib(
        "ar",
        [
            Object(Matching, "dolphin/ar/ar.c"),
            Object(Matching, "dolphin/ar/arq.c"),
        ],
    ),
    DolphinLib(
        "dsp",
        [
            Object(Matching, "dolphin/dsp/dsp.c"),
            Object(Matching, "dolphin/dsp/dsp_task.c"),
            Object(Matching, "dolphin/dsp/dsp_debug.c"),
        ],
    ),
    DolphinLib(
        "ax",
        [
            Object(Matching, "dolphin/ax/AX.c"),
        ],
    ),
    DolphinLib(
        "si",
        [
            Object(Matching, "dolphin/si/SIBios.c"),
            Object(Matching, "dolphin/si/SISamplingRate.c"),
        ],
    ),
    DolphinLib(
        "pad",
        [
            Object(Matching, "dolphin/pad/Padclamp.c"),
            Object(Matching, "dolphin/pad/Pad.c", extra_cflags=["-DVERSION_GCCP01"]),
        ],
    ),
    DolphinLib(
        "exi",
        [
            Object(Matching, "dolphin/exi/EXIBios.c"),
            Object(Matching, "dolphin/exi/EXIUart.c"),
        ],
    ),
    DolphinLib(
        "gx",
        [
            Object(Matching, "dolphin/gx/GXInit.c", extra_cflags=["-opt", "nopeephole"]),
            Object(Matching, "dolphin/gx/GXFifo.c"),
            Object(Matching, "dolphin/gx/GXMisc.c"),
            Object(Matching, "dolphin/gx/GXLight.c"),
            Object(Matching, "dolphin/gx/GXTexture.c"),
            Object(Matching, "dolphin/gx/GXBump.c"),
            Object(Matching, "dolphin/gx/GXAttr.c"),
            Object(Matching, "dolphin/gx/GXDisplayList.c"),
            Object(Matching, "dolphin/gx/GXFrameBuf.c"),
            Object(Matching, "dolphin/gx/GXDraw.c", extra_cflags=["-fp_contract", "off"]),
            Object(Matching, "dolphin/gx/GXPerf.c"),
            Object(Matching, "dolphin/gx/GXPixel.c"),
            Object(Matching, "dolphin/gx/GXSave.c"),
            Object(Matching, "dolphin/gx/GXStubs.c"),
            Object(Matching, "dolphin/gx/GXTev.c"),
            Object(Matching, "dolphin/gx/GXTransform.c"),
            Object(Matching, "dolphin/gx/GXGeometry.c"),
            Object(Matching, "dolphin/gx/GXVerifRAS.c"),
            Object(Matching, "dolphin/gx/GXVerifXF.c"),
            Object(Matching, "dolphin/gx/GXVerify.c"),
            Object(Matching, "dolphin/gx/GXVert.c"),
        ],
    ),
    DolphinLib(
        "card",
        [
            Object(Matching, "dolphin/card/CARDBios.c"),
            Object(Matching, "dolphin/card/CARDUnlock.c"),
            Object(Matching, "dolphin/card/CARDRdwr.c"),
            Object(Matching, "dolphin/card/CARDBlock.c"),
            Object(Matching, "dolphin/card/CARDDir.c"),
            Object(Matching, "dolphin/card/CARDCheck.c"),
            Object(Matching, "dolphin/card/CARDMount.c"),
            Object(Matching, "dolphin/card/CARDFormat.c"),
            Object(Matching, "dolphin/card/CARDOpen.c"),
            Object(Matching, "dolphin/card/CARDCreate.c"),
            Object(Matching, "dolphin/card/CARDRead.c"),
            Object(Matching, "dolphin/card/CARDWrite.c"),
            Object(Matching, "dolphin/card/CARDDelete.c"),
            Object(Matching, "dolphin/card/CARDStat.c"),
            Object(Matching, "dolphin/card/CARDNet.c"),
        ],
    ),
    DolphinLib(
        "axfx",
        [
            Object(Matching, "dolphin/axfx/reverb_std_callback.c", extra_cflags=["-Cpp_exceptions", "on"]),
            Object(Matching, "dolphin/axfx/reverb_std_create.c"),
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
            Object(Matching, "dolphin/vi/vi.c"),
        ],
    },
    DolphinLib(
        "thp",
        [
            Object(Matching, "dolphin/thp/THPDec.c", mw_version="GC/1.2.5"),
            Object(Matching, "dolphin/thp/THPAudio.c"),
        ],
    ),
    {
        "lib": "OdemuExi2",
        "mw_version": "GC/1.2.5",
        "cflags": cflags_base,
        "progress_category": "sdk",
        "objects": [
            Object(Matching, "dolphin/OdemuExi2/DebuggerDriver.c"),
        ],
    },
    DolphinLib(
        "odenotstub",
        [
            Object(Matching, "dolphin/odenotstub/odenotstub.c"),
        ],
    ),
    {
        "lib": "amcstubs",
        "mw_version": "GC/1.3",
        "cflags": cflags_trk,
        "progress_category": "sdk",
        "objects": [
            Object(Matching, "dolphin/amcstubs/AmcExi2Stubs.c"),
        ],
    },
    {
        "lib": "TRK_MINNOW_DOLPHIN",
        "mw_version": "GC/1.3",
        "cflags": cflags_trk,
        "progress_category": "sdk",
        "objects": [
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/mainloop.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/nubevent.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/nubinit.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/msg.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/msgbuf.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/serpoll.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/usr_put.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/dispatch.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/msghndlr.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/support.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/mutex_TRK.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/notify.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/flush_cache.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/mem_TRK.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/targimpl.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/targsupp.s"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/mpc_7xx_603e.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/main_TRK.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk_glue.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/targcont.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/target_options.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/mslsupp.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/MWCriticalSection_gc.c"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/main.c", progress_category="sdk"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/CircleBuffer.c", progress_category="sdk"),
            Object(Matching, "dolphin/TRK_MINNOW_DOLPHIN/main_gdev.c", progress_category="sdk"),
        ],
    },
    MSLLib(
        "MSL_C",
        [
            Object(Matching, "MSL_C/PPCEABI/bare/H/abort_exit.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/alloc.c", mw_version="GC/1.3", cflags=cflags_msl, extra_cflags=["-common", "off", "-inline", "auto,deferred"]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/ansi_files.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/ansi_fp.c", mw_version="GC/1.3", extra_cflags=["-inline", "all", "-inline", "auto,deferred", "-use_lmw_stmw", "on", "-char", "signed", "-str", "pool,readonly"]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/buffer_io.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/direct_io.c", mw_version="GC/1.3", extra_cflags=["-use_lmw_stmw", "on"]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/file_io.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/FILE_POS.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/mbstring.c", mw_version="GC/1.3.2r", cflags=cflags_msl),
            Object(Matching, "MSL_C/PPCEABI/bare/H/mem.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/mem_funcs.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/misc_io.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/printf.c", mw_version="GC/1.3", extra_cflags=["-use_lmw_stmw", "on", "-char", "signed"]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/string.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/wchar_io.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/ctype.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/s_copysign.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/s_frexp.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/s_ldexp.c", mw_version="GC/1.3"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/s_modf.c", mw_version="GC/1.3"),
            # Older math block: provisional MSL ownership; preserve exact TU profiles.
            Object(Matching, "MSL_C/PPCEABI/bare/H/math_float_helpers.c", mw_version="GC/1.2.5n", extra_cflags=["-inline", "off", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/inverse_trig.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", "-sym", "on", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/power_helpers.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", "-use_lmw_stmw", "on", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/trig_reduce.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-inline", "auto", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/rand.c", mw_version="GC/1.3", cflags=[*cflags_base, "-char signed"], extra_cflags=["-O0"]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/reciprocal.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/angle_vectors.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole,functions", "-inline", "auto", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/sqrtf.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-inline", "auto", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/trig16.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", "-sym", "on", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/sincosf.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole,functions", "-inline", "auto", "-sym", "on", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/sincos_approximations.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", *msl_math_extra]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/tanf_log2.c", mw_version="GC/1.2.5n", cflags=msl_math_o0_cflags, extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", "-sym", "on", *msl_math_extra]),
            Object(Matching, "dolphin/base/PPCArch_weak.c", progress_category="sdk"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/ctype_funcs.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/uart_console_io_gcn.c", mw_version="GC/1.2.5"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/hyperbolicsf.c", extra_cflags=["-lang=c++"]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/floorf.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/math_ppc.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/s_cos.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/s_atan.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/e_acos.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/float.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/exponentialsf.c", extra_cflags=["-O3,p", "-opt", "nopeephole"]),
            Object(Matching, "MSL_C/PPCEABI/bare/H/extras.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/k_rem_pio2.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/w_acos.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/w_atan2.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/w_fmod.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/w_pow.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/w_sqrt.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/common_float_tables.c"),
            Object(Matching, "MSL_C/PPCEABI/bare/H/trigf.c", mw_version="GC/1.2.5", extra_cflags=["-lang=c++"]),
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
            Object(Matching, "musyx/runtime/seq.c", extra_cflags=["-fp_contract", "off", "-inline", "noauto"]),
            Object(Matching, "musyx/runtime/mcmd_data.c"),
            Object(Matching, "musyx/runtime/synth.c", extra_cflags=["-fp_contract", "off"]),
            Object(Matching, "musyx/runtime/synth_control.c"),
            Object(Matching, "musyx/runtime/snd_synth_api.c"),
            Object(Matching, "musyx/runtime/synth_job_init.c"),
            Object(Matching, "musyx/runtime/synth_jobs.c"),
            Object(Matching, "musyx/runtime/data_tables.c"),
            Object(Matching, "musyx/runtime/mcmd_wait.c"),
            Object(Matching, "musyx/runtime/mcmd_loop.c"),
            Object(Matching, "musyx/runtime/mcmd_setup.c"),
            Object(Matching, "musyx/runtime/mcmd_volume.c"),
            Object(Matching, "musyx/runtime/mcmd_exec.c", extra_cflags=["-inline", "noauto"]),
            Object(Matching, "musyx/runtime/pitch_data.c"),
            Object(Matching, "musyx/runtime/adsr_data.c"),
            Object(Matching, "musyx/runtime/voice.c"),
            Object(Matching, "musyx/runtime/synth_ac.c"),
            Object(Matching, "musyx/runtime/synth_adsr.c"),
            Object(Matching, "musyx/runtime/synth_vsamples.c"),
            Object(Matching, "musyx/runtime/snd_groups.c", extra_cflags=["-inline", "noauto"]),
            Object(Matching, "musyx/runtime/sal_studio.c"),
            Object(Matching, "musyx/runtime/hw_dspctrl.c"),
            Object(Matching, "musyx/runtime/sal_volume.c", extra_cflags=["-fp_contract", "off", "-inline", "all"]),
            Object(Matching, "musyx/runtime/snd3dgroup.c", extra_cflags=["-fp_contract", "off", "-inline", "noauto"]),
            Object(Matching, "musyx/runtime/snd_core.c", extra_cflags=["-fp_contract", "off"]),
            Object(Matching, "musyx/runtime/snd_midictrl.c"),
            Object(Matching, "musyx/runtime/snd_service.c"),
            Object(Matching, "musyx/runtime/hw_init.c"),
            Object(Matching, "musyx/runtime/hw_break.c", mw_version="GC/2.0"),
            Object(Matching, "musyx/runtime/hw_adsr.c"),
            Object(Matching, "musyx/runtime/hw_sample.c"),
            Object(Matching, "musyx/runtime/hw_voice_start.c"),
            Object(Matching, "musyx/runtime/hw_keyoff.c"),
            Object(Matching, "musyx/runtime/hw_voice_params.c"),
            Object(Matching, "musyx/runtime/hw_volume.c"),
            Object(Matching, "musyx/runtime/hw_input.c"),
            Object(Matching, "musyx/runtime/hw_stream.c"),
            Object(Matching, "musyx/runtime/hw_aram.c"),
            Object(Matching, "musyx/runtime/hw_samplemem.c"),
            Object(Matching, "musyx/runtime/aram_queue.c"),
            Object(Matching, "musyx/runtime/aram_init.c", section_alignments={".bss": 4}),
            Object(Matching, "musyx/runtime/aram_data.c"),
            Object(Matching, "musyx/runtime/sal_ai.c"),
            Object(Matching, "musyx/runtime/sal_dsp.c"),
            Object(Matching, "musyx/runtime/sal_dsp_irqinit.c", extra_cflags=["-opt", "noschedule"]),
            Object(Matching, "musyx/runtime/sal_dsp_irq.c"),
            Object(Matching, "musyx/runtime/snd_reverb.c"),
        ],
    },
    {
        "lib": "main",
        "cflags": cflags_dll_noopt,
        "progress_category": "game",
            "objects": [
            Object(Matching, "dlls/engine/0/0.c", extra_cflags=["-inline", "noauto,deferred", "-char", "signed"]),
            Object(Matching, "dlls/engine/1_camcontrol/camcontrol.c"),
            Object(Matching, "dlls/engine/2/maketex.c", cflags=cflags_dll_noopt),
            # ObjSeq language reconstruction: declaration-order BSS and integer booleans.
            # Exact EN source link: docs/objseq_action_matching.md.
            Object(Matching, "dlls/engine/2/2.c", cflags=cflags_dll_noopt,
                   extra_cflags=["-lang=c++", "-bool", "off", "-msext", "on"]),
            Object(Matching, "dlls/engine/3/3.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/4/4.c"),
            Object(Matching, "dlls/engine/5/5.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/6/6.c"),
            Object(Matching, "dlls/engine/7/7.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/8/8.c"),
            Object(Matching, "dlls/engine/9/9.c"),
            Object(Matching, "dlls/engine/10_expgfx/expgfx.c", cflags=cflags_dll_noopt_noautoinline_deferred),
            Object(Matching, "dlls/engine/11/11.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/12/12.c"),
            Object(Matching, "dlls/engine/13/13.c"),
            Object(Matching, "dlls/engine/14/14.c"),
            Object(Matching, "dlls/engine/15/15.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/16/16.c"),
            Object(Matching, "dlls/engine/17/17.c"),
            Object(Matching, "dlls/engine/18/18.c"),
            Object(Matching, "dlls/engine/19/19.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/20_Hcurves/Hcurves.c"),
            Object(Matching, "dlls/engine/20_Hcurves/Hcurves_romcurve.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/21/21.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/22/22.c", cflags=cflags_dll_noopt_noautoinline_level3),
            Object(Matching, "dlls/engine/23/23.c", cflags=cflags_dll_noopt_noautoinline_deferred),
            Object(Matching, "dlls/engine/24/24.c"),
            Object(Matching, "dlls/engine/25/25.c"),
            Object(Matching, "dlls/engine/26/26.c"),
            Object(Matching, "dlls/engine/27/27.c"),
            Object(Matching, "dlls/engine/28/28.c"),
            Object(Matching, "dlls/engine/29/29.c"),
            Object(Matching, "dlls/engine/30/30.c"),
            Object(Matching, "dlls/engine/31/31.c"),
            Object(Matching, "dlls/engine/32/32.c"),
            Object(Matching, "dlls/engine/33/33.c"),
            Object(Matching, "dlls/engine/34/34.c"),
            Object(Matching, "dlls/engine/35/35.c"),
            Object(Matching, "dlls/engine/36/36.c"),
            Object(Matching, "dlls/engine/37/37.c"),
            Object(Matching, "dlls/engine/38/38.c"),
            Object(Matching, "dlls/engine/39/39.c"),
            Object(Matching, "dlls/engine/40/40.c"),
            Object(Matching, "dlls/engine/41/41.c"),
            Object(Matching, "dlls/engine/42/42.c"),
            Object(Matching, "dlls/engine/43/43.c"),
            Object(Matching, "dlls/engine/44/44.c"),
            Object(Matching, "dlls/engine/45/45.c"),
            Object(Matching, "dlls/engine/46/46.c"),
            Object(Matching, "dlls/engine/47/47.c"),
            Object(Matching, "dlls/engine/48/48.c"),
            Object(Matching, "dlls/engine/49/49.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/engine/50/50.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(Matching, "dlls/engine/51/51.c"),
            Object(Matching, "dlls/engine/52_n_attractmode/n_attractmode.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/53/53.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/engine/54/54.c"),
            Object(Matching, "dlls/engine/55/55.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/engine/56/56.c"),
            Object(Matching, "dlls/engine/57/57.c"),
            Object(Matching, "dlls/engine/58/58.c"),
            Object(Matching, "dlls/engine/59/59.c"),
            Object(Matching, "dlls/engine/60/60.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/engine/61/61.c"),
            Object(Matching, "dlls/engine/62/62.c"),
            Object(Matching, "dlls/engine/63/63.c"),
            Object(Matching, "dlls/engine/64/64.c"),
            Object(Matching, "dlls/engine/65/65.c", extra_cflags=["-inline", "noauto"]),
            Object(Matching, "dlls/engine/66/66.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/67/67.c"),
            Object(Matching, "dlls/engine/68/68.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/69/69.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/engine/70/70.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(Matching, "dlls/engine/71/71.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/72/72.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/73/73.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/74/74.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(Matching, "dlls/engine/75/75.c", extra_cflags=["-inline", "auto,deferred"]),
            Object(Matching, "dlls/engine/76/76.c"),
            Object(Matching, "dlls/engine/77/77.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/engine/78/78.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(Matching, "dlls/engine/79/79.c"),
            Object(Matching, "dlls/engine/80/80.c"),
            Object(Matching, "dlls/engine/81/81.c"),
            Object(Matching, "dlls/engine/82/82.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/engine/83/83.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/engine/84/84.c"),
            Object(Matching, "dlls/engine/85/85.c"),
            Object(Matching, "dlls/engine/86/86.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(Matching, "dlls/engine/87/87.c"),
            Object(Matching, "dlls/engine/88/88.c"),

            Object(Matching, "dlls/modgfx/89/89.c"),
            Object(Matching, "dlls/modgfx/90/90.c"),
            Object(Matching, "dlls/modgfx/91/91.c"),
            Object(Matching, "dlls/modgfx/92/92.c"),
            Object(Matching, "dlls/modgfx/93/93.c"),
            Object(Matching, "dlls/modgfx/94/94.c"),
            Object(Matching, "dlls/modgfx/95/95.c"),
            Object(Matching, "dlls/modgfx/96/96.c"),
            Object(Matching, "dlls/modgfx/97/97.c"),
            Object(Matching, "dlls/modgfx/98/98.c"),
            Object(Matching, "dlls/modgfx/99/99.c"),
            Object(Matching, "dlls/modgfx/100/100.c"),
            Object(Matching, "dlls/modgfx/101/101.c"),
            Object(Matching, "dlls/modgfx/102/102.c"),
            Object(Matching, "dlls/modgfx/103/103.c"),
            Object(Matching, "dlls/modgfx/104/104.c"),
            Object(Matching, "dlls/modgfx/105/105.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/modgfx/106/106.c"),
            Object(Matching, "dlls/modgfx/107/107.c"),
            Object(Matching, "dlls/modgfx/108/108.c"),
            Object(Matching, "dlls/modgfx/109/109.c"),
            Object(Matching, "dlls/modgfx/110/110.c"),
            Object(Matching, "dlls/modgfx/111/111.c"),
            Object(Matching, "dlls/modgfx/112/112.c"),
            Object(Matching, "dlls/modgfx/113/113.c"),
            Object(Matching, "dlls/modgfx/114/114.c"),
            Object(Matching, "dlls/modgfx/115/115.c"),
            Object(Matching, "dlls/modgfx/116/116.c"),
            Object(Matching, "dlls/modgfx/117/117.c"),
            Object(Matching, "dlls/modgfx/118/118.c"),
            Object(Matching, "dlls/modgfx/119/119.c"),
            Object(Matching, "dlls/modgfx/120/120.c"),
            Object(Matching, "dlls/modgfx/121/121.c"),
            Object(Matching, "dlls/modgfx/122/122.c"),
            Object(Matching, "dlls/modgfx/123/123.c"),
            Object(Matching, "dlls/modgfx/124/124.c"),
            Object(Matching, "dlls/modgfx/125/125.c"),
            Object(Matching, "dlls/modgfx/126/126.c"),
            Object(Matching, "dlls/modgfx/127/127.c"),
            Object(Matching, "dlls/modgfx/128/128.c"),
            Object(Matching, "dlls/modgfx/129/129.c"),
            Object(Matching, "dlls/modgfx/130/130.c"),
            Object(Matching, "dlls/modgfx/131/131.c"),
            Object(Matching, "dlls/modgfx/132/132.c"),
            Object(Matching, "dlls/modgfx/133/133.c"),
            Object(Matching, "dlls/modgfx/134/134.c"),
            Object(Matching, "dlls/modgfx/135/135.c"),
            Object(Matching, "dlls/modgfx/136/136.c"),
            Object(Matching, "dlls/modgfx/137/137.c"),
            Object(Matching, "dlls/modgfx/138/138.c"),
            Object(Matching, "dlls/modgfx/139/139.c"),
            Object(Matching, "dlls/modgfx/140/140.c"),
            Object(Matching, "dlls/modgfx/141/141.c"),
            Object(Matching, "dlls/modgfx/142/142.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/modgfx/143/143.c"),
            Object(Matching, "dlls/modgfx/144/144.c"),
            Object(Matching, "dlls/modgfx/145/145.c"),
            Object(Matching, "dlls/modgfx/146/146.c"),
            Object(Matching, "dlls/modgfx/147/147.c"),
            Object(Matching, "dlls/modgfx/148/148.c"),
            Object(Matching, "dlls/modgfx/149/149.c"),
            Object(Matching, "dlls/modgfx/150/150.c"),
            Object(Matching, "dlls/modgfx/151/151.c"),
            Object(Matching, "dlls/modgfx/152/152.c"),
            Object(Matching, "dlls/modgfx/153/153.c"),
            Object(Matching, "dlls/modgfx/154/154.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/modgfx/155/155.c"),
            Object(Matching, "dlls/modgfx/156/156.c", extra_cflags=["-opt", "level=3,nopropagation"]),
            Object(Matching, "dlls/modgfx/157/157.c"),
            Object(Matching, "dlls/modgfx/158/158.c"),
            Object(Matching, "dlls/modgfx/159/159.c"),
            Object(Matching, "dlls/modgfx/160/160.c"),
            Object(Matching, "dlls/modgfx/161/161.c"),
            Object(Matching, "dlls/modgfx/162/162.c"),
            Object(Matching, "dlls/modgfx/163/163.c"),
            Object(Matching, "dlls/modgfx/164/164.c"),
            Object(Matching, "dlls/modgfx/165/165.c"),
            Object(Matching, "dlls/modgfx/166/166.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/modgfx/167/167.c"),
            Object(Matching, "dlls/modgfx/168/168.c"),
            Object(Matching, "dlls/modgfx/169/169.c"),
            Object(Matching, "dlls/modgfx/170/170.c"),

            Object(Matching, "dlls/projgfx/171/171.c"),
            Object(Matching, "dlls/projgfx/172/172.c"),
            Object(Matching, "dlls/projgfx/173/173.c"),
            Object(Matching, "dlls/projgfx/174/174.c"),
            Object(Matching, "dlls/projgfx/175/175.c"),
            Object(Matching, "dlls/projgfx/176/176.c"),
            Object(Matching, "dlls/projgfx/177/177.c"),
            Object(Matching, "dlls/projgfx/178/178.c"),
            Object(Matching, "dlls/projgfx/179/179.c"),
            Object(Matching, "dlls/projgfx/180/180.c"),
            Object(Matching, "dlls/projgfx/181/181.c"),
            Object(Matching, "dlls/projgfx/182/182.c"),
            Object(Matching, "dlls/projgfx/183/183.c"),
            Object(Matching, "dlls/projgfx/184/184.c"),
            Object(Matching, "dlls/projgfx/185/185.c"),
            Object(Matching, "dlls/projgfx/186/186.c"),
            Object(Matching, "dlls/projgfx/187/187.c"),
            Object(Matching, "dlls/projgfx/188/188.c"),
            Object(Matching, "dlls/projgfx/189/189.c"),
            Object(Matching, "dlls/projgfx/190/190.c"),
            Object(Matching, "dlls/projgfx/191/191.c"),
            Object(Matching, "dlls/projgfx/192/192.c"),
            Object(Matching, "dlls/projgfx/193/193.c"),
            Object(Matching, "dlls/projgfx/194/194.c"),

            Object(Matching, "dlls/objects/195_Player/player.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/196_Tricky/tricky.c", cflags=cflags_dll_noopt, extra_cflags=["-char signed", "-inline deferred"]),
            Object(Matching, "dlls/objects/197/197.c"),
            Object(Matching, "dlls/objects/198_AnimatedObj/AnimatedObj.c"),
            Object(Matching, "dlls/objects/199_DIM2RoofRub/DIM2RoofRub.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/objects/200_DepthOfFieldPoint/DepthOfFieldPoint.c"),
            Object(Matching, "dlls/objects/201_Baddie/Baddie.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/battledroid.c"),
            Object(Matching, "dlls/objects/202/sharpclaw.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/guardclaw.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/gcrobotpatrol.c", cflags=cflags_dll_noopt_nocse_noautoinline),
            Object(Matching, "dlls/objects/202/mikaladon.c"),
            Object(Matching, "dlls/objects/202/vambat.c"),
            Object(Matching, "dlls/objects/202/kooshy.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/weevil.c"),
            Object(Matching, "dlls/objects/202/pinpon.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/rachnop.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/spittingeba.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/wb.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/202/mutatedeba.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/hoodedzyck.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/202/firecrawler.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/hagabon_mk2.c"),
            Object(Matching, "dlls/objects/202/snowworm.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/202/baddiewhirlpool.c"),
            Object(Matching, "dlls/objects/202/202.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/203/203.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/204_ChukChuk/ChukChuk.c", cflags=cflags_dll_noopt_noprop_noinline),
            Object(Matching, "dlls/objects/205_IceBall/IceBall.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/206/206.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/207_CannonClaw/CannonClaw.c"),
            Object(Matching, "dlls/objects/208_Grimble/Grimble.c"),
            Object(Matching, "dlls/objects/209_TumbleWeedB/TumbleWeedB.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/211/211.c"),
            Object(Matching, "dlls/objects/212_SkeetlaWall/SkeetlaWall.c"),
            Object(Matching, "dlls/objects/213_Kaldachom/Kaldachom.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/214_KaldachomMe/KaldachomMe.c"),
            Object(Matching, "dlls/objects/215/215.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/216_PinPonSpike/PinPonSpike.c"),
            Object(Matching, "dlls/objects/217_Pollen/Pollen.c"),
            Object(Matching, "dlls/objects/218/218.c"),
            Object(Matching, "dlls/objects/219_MikaBomb/MikaBomb.c"),
            Object(Matching, "dlls/objects/220_MikaBombSha/MikaBombSha.c"),
            Object(Matching, "dlls/objects/221_GCbaddieShi/GCbaddieShi.c"),
            Object(Matching, "dlls/objects/222_baddieInter/baddieInter.c"),
            Object(Matching, "dlls/objects/223_Hagabon/Hagabon.c"),
            Object(Matching, "dlls/objects/224_SwarmBaddie/SwarmBaddie.c"),
            Object(Matching, "dlls/objects/225_WispBaddie/WispBaddie.c"),
            Object(Matching, "dlls/objects/226/226.c"),
            Object(Matching, "dlls/objects/227/227.c", section_alignments={".data": 4}),
            Object(Matching, "dlls/objects/228/228.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/229/229.c"),
            Object(Matching, "dlls/objects/230_ReStartMark/ReStartMark.c"),
            Object(Matching, "dlls/objects/231/231.c"),
            Object(Matching, "dlls/objects/232_Checkpoint4/Checkpoint4.c"),
            Object(Matching, "dlls/objects/233_Setuppoint/Setuppoint.c"),
            Object(Matching, "dlls/objects/234_Sideload/Sideload.c"),
            Object(Matching, "dlls/objects/235/235.c"),
            Object(Matching, "dlls/objects/236_InfoPoint/InfoPoint.c"),
            Object(Matching, "dlls/objects/237/237.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/238_EffectBox/EffectBox.c"),
            Object(Matching, "dlls/objects/239/239.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/240_WarpPoint/WarpPoint.c"),
            Object(Matching, "dlls/objects/241_InvHit/InvHit.c"),
            Object(Matching, "dlls/objects/242_iceblast/iceblast.c"),
            Object(Matching, "dlls/objects/243_flameblast/flameblast.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(Matching, "dlls/objects/244/244.c"),
            Object(Matching, "dlls/objects/245_SidekickBal/SidekickBal.c"),
            Object(Matching, "dlls/objects/246_Area/Area.c"),
            Object(Matching, "dlls/objects/247/247.c"),
            Object(Matching, "dlls/objects/248_LevelName/LevelName.c"),
            Object(Matching, "dlls/objects/249/249.c"),
            Object(Matching, "dlls/objects/250_InvisibleHi/InvisibleHi.c"),
            Object(Matching, "dlls/objects/251/251.c"),
            Object(Matching, "dlls/objects/252/252.c"),
            Object(Matching, "dlls/objects/253/253.c"),
            Object(Matching, "dlls/objects/254_MagicPlant/MagicPlant.c", cflags=cflags_dll_noopt_nocse_noautoinline, extra_cflags=["-inline", "auto,deferred"]),
            Object(Matching, "dlls/objects/255/255.c"),
            Object(Matching, "dlls/objects/256_TrickyWarp/TrickyWarp.c"),
            Object(Matching, "dlls/objects/257_TrickyGuard/TrickyGuard.c"),
            Object(Matching, "dlls/objects/258_StayPoint/StayPoint.c"),
            Object(Matching, "dlls/objects/259_CurveFish/CurveFish.c"),
            Object(Matching, "dlls/objects/260_SmallBasket/SmallBasket.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/objects/261_LargeCrate/LargeCrate.c"),
            Object(Matching, "dlls/objects/262/262.c"),
            Object(Matching, "dlls/objects/263/263.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(Matching, "dlls/objects/264_EndObject/EndObject.c"),
            Object(Matching, "dlls/objects/265/265.c"),
            Object(Matching, "dlls/objects/266_Fall_Ladder/Fall_Ladder.c"),
            Object(Matching, "dlls/objects/267_FireFlyLant/FireFlyLant.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/268_LanternFire/LanternFire.c", cflags=cflags_dll_noopt_noautoinline, extra_cflags=["-inline", "noauto,deferred"]),
            Object(Matching, "dlls/objects/269_PortalSpell/PortalSpell.c"),
            Object(Matching, "dlls/objects/270/270.c"),
            Object(Matching, "dlls/objects/271_MMP_Bridge/MMP_Bridge.c"),
            Object(Matching, "dlls/objects/272/272.c"),
            Object(Matching, "dlls/objects/273/273.c"),
            Object(Matching, "dlls/objects/274/274.c"),
            Object(Matching, "dlls/objects/275/275.c"),
            Object(Matching, "dlls/objects/276_IMMultiSeq/IMMultiSeq.c"),
            Object(Matching, "dlls/objects/277/277.c"),
            Object(Matching, "dlls/objects/278_WM_Column/WM_Column.c"),
            Object(Matching, "dlls/objects/279_AppleOnTree/AppleOnTree.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/280_Duster/Duster.c"),
            Object(Matching, "dlls/objects/281_coldWaterCo/coldWaterCo.c"),
            Object(Matching, "dlls/objects/282/282.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/283_Landed_Arwi/Landed_Arwi.c"),
            Object(Matching, "dlls/objects/284/284.c", extra_cflags=["-inline", "auto,deferred"]),
            Object(Matching, "dlls/objects/285/285.c"),
            Object(Matching, "dlls/objects/286_MagicCaveBo/MagicCaveBo.c"),
            Object(Matching, "dlls/objects/287_MagicCaveTo/MagicCaveTo.c"),
            Object(Matching, "dlls/objects/288_TrickyGuard/TrickyGuard.c"),
            Object(Matching, "dlls/objects/289/289.c"),
            Object(Matching, "dlls/objects/290_CCTestInfot/CCTestInfot.c"),
            Object(Matching, "dlls/objects/291_fuelCell/fuelCell.c"),
            Object(Matching, "dlls/objects/292/292.c"),
            Object(Matching, "dlls/objects/293_curve/curve.c"),
            Object(Matching, "dlls/objects/294/294.c"),
            Object(Matching, "dlls/objects/295/295.c"),
            Object(Matching, "dlls/objects/296_KT_Torch/KT_Torch.c"),
            Object(Matching, "dlls/objects/297_CampFire/CampFire.c"),
            Object(Matching, "dlls/objects/298_CFCrate/CFCrate.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/objects/299_FXEmit/FXEmit.c"),
            Object(Matching, "dlls/objects/300_Transporter/Transporter.c"),
            Object(Matching, "dlls/objects/301_LFXEmitter/LFXEmitter.c"),
            Object(Matching, "dlls/objects/302/302.c"),
            Object(Matching, "dlls/objects/303_BarrelPad/BarrelPad.c"),
            Object(Matching, "dlls/objects/304_AreaFXEmit/AreaFXEmit.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/305/305.c"),
            Object(Matching, "dlls/objects/306_WaterFallSp/WaterFallSp.c"),
            Object(Matching, "dlls/objects/307_sfxPlayer/sfxPlayer.c"),
            Object(Matching, "dlls/objects/308_texscroll2/texscroll2.c"),
            Object(Matching, "dlls/objects/309_texscroll/texscroll.c"),
            Object(Matching, "dlls/objects/310_WaveAnimato/WaveAnimato.c"),
            Object(Matching, "dlls/objects/311_AlphaAnimat/AlphaAnimat.c"),
            Object(Matching, "dlls/objects/312_GroundAnima/GroundAnima.c"),
            Object(Matching, "dlls/objects/313_HitAnimator/HitAnimator.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/314_VisAnimator/VisAnimator.c"),
            Object(Matching, "dlls/objects/315_WallAnimato/WallAnimato.c"),
            Object(Matching, "dlls/objects/316_XYZAnimator/XYZAnimator.c"),
            Object(Matching, "dlls/objects/317_ExplodeAnim/ExplodeAnim.c"),
            Object(Matching, "dlls/objects/318/318.c"),
            Object(Matching, "dlls/objects/319_TexFrameAni/TexFrameAni.c"),
            Object(Matching, "dlls/objects/320_fogControl/fogControl.c"),
            Object(Matching, "dlls/objects/321_Lightning/Lightning.c"),
            Object(Matching, "dlls/objects/322_FElevContro/FElevContro.c"),
            Object(Matching, "dlls/objects/323_FEseqobject/FEseqobject.c"),
            Object(Matching, "dlls/objects/324/324.c"),
            Object(Matching, "dlls/objects/325_CloudPrison/CloudPrison.c"),
            Object(Matching, "dlls/objects/326_CloudShipCo/CloudShipCo.c"),
            Object(Matching, "dlls/objects/327/327.c"),
            Object(Matching, "dlls/objects/328_CFGuardian/CFGuardian.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(Matching, "dlls/objects/329/329.c"),
            Object(Matching, "dlls/objects/330_CFPowerBase/CFPowerBase.c"),
            Object(Matching, "dlls/objects/331_CFMainCryst/CFMainCryst.c"),
            Object(Matching, "dlls/objects/332/332.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/333_LaserBeam/LaserBeam.c"),
            Object(Matching, "dlls/objects/334_CFPrisonGua/CFPrisonGua.c"),
            Object(Matching, "dlls/objects/335_CFPrisonUnc/CFPrisonUnc.c"),
            Object(Matching, "dlls/objects/336_GCRobotLigh/GCRobotLigh.c"),
            Object(Matching, "dlls/objects/337_CFScalesGal/CFScalesGal.c"),
            Object(Matching, "dlls/objects/338_CF_ObjCreat/CF_ObjCreat.c"),
            Object(Matching, "dlls/objects/339_CFPerch/CFPerch.c"),
            Object(Matching, "dlls/objects/340/340.c"),
            Object(Matching, "dlls/objects/341/341.c"),
            Object(Matching, "dlls/objects/342/342.c"),
            Object(Matching, "dlls/objects/343_SpiritDoorS/SpiritDoorS.c"),
            Object(Matching, "dlls/objects/344/344.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/345/345.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/346/346.c"),
            Object(Matching, "dlls/objects/347_CFForceFiel/CFForceFiel.c"),
            Object(Matching, "dlls/objects/348_CFForceFiel/CFForceFiel.c"),
            Object(Matching, "dlls/objects/349/349.c"),
            Object(Matching, "dlls/objects/350/350.c"),
            Object(Matching, "dlls/objects/351/351.c"),
            Object(Matching, "dlls/objects/352/352.c"),
            Object(Matching, "dlls/objects/353_CFTreasRobo/CFTreasRobo.c"),
            Object(Matching, "dlls/objects/354_CFMagicWall/CFMagicWall.c"),
            Object(Matching, "dlls/objects/355/355.c"),
            Object(Matching, "dlls/objects/356_CFLevelCont/CFLevelCont.c"),
            Object(Matching, "dlls/objects/357_CFRemovalSh/CFRemovalSh.c"),
            Object(Matching, "dlls/objects/358/358.c"),
            Object(Matching, "dlls/objects/359_SpiritDoorL/SpiritDoorL.c", extra_cflags=["-inline", "auto,deferred"]),
            Object(Matching, "dlls/objects/360_HoloPoint/HoloPoint.c"),
            Object(Matching, "dlls/objects/361_IMIceMounta/IMIceMounta.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/362_CRrockfall/CRrockfall.c", cflags=cflags_dll_noopt_noprop_noautoinline),
            Object(Matching, "dlls/objects/363/363.c"),
            Object(Matching, "dlls/objects/364/364.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/365_IMIcePillar/IMIcePillar.c"),
            Object(Matching, "dlls/objects/366_IMAnimSpace/IMAnimSpace.c"),
            Object(Matching, "dlls/objects/367_IMSpaceThru/IMSpaceThru.c"),
            Object(Matching, "dlls/objects/368_IMSpaceRing/IMSpaceRing.c"),
            Object(Matching, "dlls/objects/369_IMSpaceRing/IMSpaceRing.c"),
            Object(Matching, "dlls/objects/370_LINKB_levco/LINKB_levco.c"),
            Object(Matching, "dlls/objects/371_LINK_levcon/LINK_levcon.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/372_CCriverflow/CCriverflow.c"),
            Object(Matching, "dlls/objects/373_DFropenode/DFropenode.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/374_DFSH_Door1S/DFSH_Door1S.c"),
            Object(Matching, "dlls/objects/375/375.c"),
            Object(Matching, "dlls/objects/376_DFSH_Shrine/DFSH_Shrine.c"),
            Object(Matching, "dlls/objects/377_DFSH_ObjCre/DFSH_ObjCre.c"),
            Object(Matching, "dlls/objects/378_SpiritPrize/SpiritPrize.c"),
            Object(Matching, "dlls/objects/379_DFSH_LaserB/DFSH_LaserB.c"),
            Object(Matching, "dlls/objects/380_GCRobotPatr/GCRobotPatr.c"),
            Object(Matching, "dlls/objects/381/381.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/382_MMP_levelco/MMP_levelco.c"),
            Object(Matching, "dlls/objects/383/383.c"),
            Object(Matching, "dlls/objects/384_MMP_asteroi/MMP_asteroi.c"),
            Object(Matching, "dlls/objects/385_MMP_trenchF/MMP_trenchF.c"),
            Object(Matching, "dlls/objects/386_MMP_moonroc/MMP_moonroc.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/387_MMP_gyserve/MMP_gyserve.c"),
            Object(Matching, "dlls/objects/388/388.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/389_CCgasvent/CCgasvent.c"),
            Object(Matching, "dlls/objects/390_CCgasventCo/CCgasventCo.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/391_CCqueen/CCqueen.c"),
            Object(Matching, "dlls/objects/392_CClightfoot/CClightfoot.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/393_CCSharpclaw/CCSharpclaw.c"),
            Object(Matching, "dlls/objects/394_CCpedstal/CCpedstal.c"),
            Object(Matching, "dlls/objects/395_CClevcontro/CClevcontro.c"),
            Object(Matching, "dlls/objects/396_MMSH_Shrine/MMSH_Shrine.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/397_MMSH_Scales/MMSH_Scales.c"),
            Object(Matching, "dlls/objects/398_MMSH_WaterS/MMSH_WaterS.c"),
            Object(Matching, "dlls/objects/399_ECSH_Shrine/ECSH_Shrine.c"),
            Object(Matching, "dlls/objects/400_ECSH_Cup/ECSH_Cup.c"),
            Object(Matching, "dlls/objects/401_ECSH_Creato/ECSH_Creato.c"),
            Object(Matching, "dlls/objects/402_GPSH_Shrine/GPSH_Shrine.c"),
            Object(Matching, "dlls/objects/403_GPSH_ObjCre/GPSH_ObjCre.c"),
            Object(Matching, "dlls/objects/404_GPSH_Scene/GPSH_Scene.c"),
            Object(Matching, "dlls/objects/405_DBSH_Shrine/DBSH_Shrine.c"),
            Object(Matching, "dlls/objects/406_DBSH_Symbol/DBSH_Symbol.c"),
            Object(Matching, "dlls/objects/407/407.c"),
            Object(Matching, "dlls/objects/408_NWSH_levcon/NWSH_levcon.c"),
            Object(Matching, "dlls/objects/409/409.c"),
            Object(Matching, "dlls/objects/410/410.c"),
            Object(Matching, "dlls/objects/411/411.c"),
            Object(Matching, "dlls/objects/412/412.c"),
            Object(Matching, "dlls/objects/413/413.c"),
            Object(Matching, "dlls/objects/414/414.c"),
            Object(Matching, "dlls/objects/415_NW_treebrid/NW_treebrid.c"),
            Object(Matching, "dlls/objects/416_NW_geyser/NW_geyser.c"),
            Object(Matching, "dlls/objects/417/417.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/418_NW_tricky/NW_tricky.c"),
            Object(Matching, "dlls/objects/419/419.c"),
            Object(Matching, "dlls/objects/420/420.c"),
            Object(Matching, "dlls/objects/421_NW_levcontr/NW_levcontr.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/422_SH_tricky/SH_tricky.c"),
            Object(Matching, "dlls/objects/423/423.c", cflags=cflags_dll_noopt_nodead),
            Object(Matching, "dlls/objects/424_SH_killermu/SH_killermu.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(Matching, "dlls/objects/425_BombPlant/BombPlant.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/426_BombPlantSp/BombPlantSp.c", cflags=cflags_dll_noopt_noautoinline, extra_cflags=["-inline", "noauto,deferred"]),
            Object(Matching, "dlls/objects/427_BombPlantin/BombPlantin.c"),
            Object(Matching, "dlls/objects/428_SH_queenear/SH_queenear.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/429_SH_thorntai/SHthorntail.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/430_SH_LevelCon/SH_LevelCon.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/431_SH_swaplift/SH_swaplift.c"),
            Object(Matching, "dlls/objects/432_SH_swapston/SH_swapston.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/433_SH_staff/SH_staff.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/434_SH_staffHaz/SH_staffHaz.c"),
            Object(Matching, "dlls/objects/435_SH_Beacon/SH_Beacon.c"),
            Object(Matching, "dlls/objects/436_SH_EmptyTum/SH_EmptyTum.c"),
            Object(Matching, "dlls/objects/437/437.c", cflags=[*cflags_dll_noopt, "-inline", "noauto"]),
            Object(Matching, "dlls/objects/438_SC_levelcon/SC_levelcon.c"),
            Object(Matching, "dlls/objects/439/439.c", cflags=cflags_dll_noopt_nocse_noautoinline),
            Object(Matching, "dlls/objects/440_SC_totempol/SC_totempol.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/441_SC_Cloudrun/SC_Cloudrun.c"),
            Object(Matching, "dlls/objects/442_SC_totempuz/SC_totempuz.c"),
            Object(Matching, "dlls/objects/443_SC_totembon/SC_totembon.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/444_SC_totemstr/SC_totemstr.c"),
            Object(Matching, "dlls/objects/445/445.c"),
            Object(Matching, "dlls/objects/446/446.c"),
            Object(Matching, "dlls/objects/447_DIMLavaBall/DIMLavaBall.c"),
            Object(Matching, "dlls/objects/448_DIMLogFire/DIMLogFire.c"),
            Object(Matching, "dlls/objects/449_DIMSnowBall/DIMSnowBall.c"),
            Object(Matching, "dlls/objects/450_DIMSnowBall/DIMSnowBall.c"),
            Object(Matching, "dlls/objects/451_DIMGate/DIMGate.c"),
            Object(Matching, "dlls/objects/452_DIMIceWall/DIMIceWall.c"),
            Object(Matching, "dlls/objects/453_DIMBarrier/DIMBarrier.c"),
            Object(Matching, "dlls/objects/454_DIMCannon/DIMCannon.c"),
            Object(Matching, "dlls/objects/455_DIMLavaSmas/DIMLavaSmas.c", cflags=cflags_dll_noopt_noprop_noinline),
            Object(Matching, "dlls/objects/456_DIMBridgeCo/DIMBridgeCo.c"),
            Object(Matching, "dlls/objects/457_DIMDismount/DIMDismount.c"),
            Object(Matching, "dlls/objects/458_DIMExplosio/DIMExplosio.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/459_DIMWoodDoor/DIMWoodDoor.c"),
            Object(Matching, "dlls/objects/460_DIMMagicBri/DIMMagicBri.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/461_DIM_LevelCo/DIM_LevelCo.c"),
            Object(Matching, "dlls/objects/462/462.c"),
            Object(Matching, "dlls/objects/463/463.c"),
            Object(Matching, "dlls/objects/464_DIM_tricky/DIM_tricky.c"),
            Object(Matching, "dlls/objects/465_DIMTruthHor/DIMTruthHor.c"),
            Object(Matching, "dlls/objects/466_WORLDplanet/WORLDplanet.c"),
            Object(Matching, "dlls/objects/467/467.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/468_WORLDAstero/WORLDAstero.c"),
            Object(Matching, "dlls/objects/469_DIM2Conveyo/DIM2Conveyo.c"),
            Object(Matching, "dlls/objects/470/470.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/471_DIM2SnowBal/DIM2SnowBal.c"),
            Object(Matching, "dlls/objects/472_DIM2PathGen/DIM2PathGen.c"),
            Object(Matching, "dlls/objects/473_DIM2PrisonM/DIM2PrisonM.c"),
            Object(Matching, "dlls/objects/474/474.c"),
            Object(Matching, "dlls/objects/475/475.c"),
            Object(Matching, "dlls/objects/476_DIM2IceFloe/DIM2IceFloe.c"),
            Object(Matching, "dlls/objects/477_DIM2Icicle/DIM2Icicle.c"),
            Object(Matching, "dlls/objects/478_DIM2LavaCon/DIM2LavaCon.c"),
            Object(Matching, "dlls/objects/479/479.c"),
            Object(Matching, "dlls/objects/480_DIM_Boss/DIM_Boss.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/481_DIM_BossGut/DIM_BossGut.c"),
            Object(Matching, "dlls/objects/482_DIM_BossTon/DIM_BossTon.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/objects/483_DIM_BossGut/DIM_BossGut.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/484_MAGICMaker/MAGICMaker.c"),
            Object(Matching, "dlls/objects/485_DIM_BossSpi/DIM_BossSpi.c"),
            Object(Matching, "dlls/objects/486_DIMbosscrac/DIMbosscrac.c"),
            Object(Matching, "dlls/objects/487_DIMbossfire/DIMbossfire.c"),
            Object(Matching, "dlls/objects/488_SB_Galleon/SB_Galleon.c"),
            Object(Matching, "dlls/objects/489_SB_Propelle/SB_Propelle.c"),
            Object(Matching, "dlls/objects/490_SB_ShipHead/SB_ShipHead.c"),
            Object(Matching, "dlls/objects/491_SB_ShipMast/SB_ShipMast.c"),
            Object(Matching, "dlls/objects/492_SB_ShipGun/SB_ShipGun.c"),
            Object(Matching, "dlls/objects/493_SB_FireBall/SB_FireBall.c"),
            Object(Matching, "dlls/objects/494_SB_CannonBa/SB_CannonBa.c"),
            Object(Matching, "dlls/objects/495_SB_CloudBal/SB_CloudBal.c"),
            Object(Matching, "dlls/objects/496_SB_KyteCage/SB_KyteCage.c"),
            Object(Matching, "dlls/objects/497_SB_SeqDoor/SB_SeqDoor.c"),
            Object(Matching, "dlls/objects/498_SB_CageKyte/SB_CageKyte.c"),
            Object(Matching, "dlls/objects/499_SB_MiniFire/SB_MiniFire.c"),
            Object(Matching, "dlls/objects/500/500.c"),
            Object(Matching, "dlls/objects/501/501.c"),
            Object(Matching, "dlls/objects/502/502.c"),
            Object(Matching, "dlls/objects/503_SB_ShipGunB/SB_ShipGunB.c"),
            Object(Matching, "dlls/objects/504_WM_Galleon/WM_Galleon.c"),
            Object(Matching, "dlls/objects/505_WM_ObjCreat/WM_ObjCreat.c"),
            Object(Matching, "dlls/objects/506_WM_seqobjec/WM_seqobjec.c"),
            Object(Matching, "dlls/objects/507/507.c"),
            Object(Matching, "dlls/objects/508/508.c"),
            Object(Matching, "dlls/objects/509_WM_LaserTar/WM_LaserTar.c"),
            Object(Matching, "dlls/objects/510/510.c"),
            Object(Matching, "dlls/objects/511/511.c"),
            Object(Matching, "dlls/objects/512/512.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/513_WM_colrise/WM_colrise.c"),
            Object(Matching, "dlls/objects/514/514.c"),
            Object(Matching, "dlls/objects/515/515.c"),
            Object(Matching, "dlls/objects/516_WM_Torch/WM_Torch.c"),
            Object(Matching, "dlls/objects/517_WM_Vein/WM_Vein.c"),
            Object(Matching, "dlls/objects/518_LightSource/LightSource.c"),
            Object(Matching, "dlls/objects/519_WM_Worm/WM_Worm.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/520_WM_Wallpowe/WM_Wallpowe.c"),
            Object(Matching, "dlls/objects/521_WM_LevelCon/WM_LevelCon.c"),
            Object(Matching, "dlls/objects/522_WM_GeneralS/WM_GeneralS.c"),
            Object(Matching, "dlls/objects/523_FireFly/FireFly.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/524_WM_spiritpl/WM_spiritpl.c"),
            Object(Matching, "dlls/objects/525_WM_seqpoint/WM_seqpoint.c"),
            Object(Matching, "dlls/objects/526_WM_sun/WM_sun.c"),
            Object(Matching, "dlls/objects/527_WM_SpiritSe/WM_SpiritSe.c"),
            Object(Matching, "dlls/objects/528_WM_Planets/WM_Planets.c"),
            Object(Matching, "dlls/objects/529/529.c", cflags=cflags_dll_noopt_nodead_noautoinline),
            Object(Matching, "dlls/objects/530/530.c"),
            Object(Matching, "dlls/objects/531_WM_VConsole/WM_VConsole.c"),
            Object(Matching, "dlls/objects/532_WM_TransTop/WM_TransTop.c"),
            Object(Matching, "dlls/objects/533_WM_newcryst/WM_newcryst.c"),
            Object(Matching, "dlls/objects/534_VFP_LevelCo/VFP_LevelCo.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/535_VFP_ObjCrea/VFP_ObjCrea.c"),
            Object(Matching, "dlls/objects/536_VFP_MiniFir/VFP_MiniFir.c"),
            Object(Matching, "dlls/objects/537/537.c"),
            Object(Matching, "dlls/objects/538_VFP_statueb/VFP_statueb.c"),
            Object(Matching, "dlls/objects/539/539.c"),
            Object(Matching, "dlls/objects/540_VFP_Ladders/VFP_Ladders.c"),
            Object(Matching, "dlls/objects/541/541.c"),
            Object(Matching, "dlls/objects/542_VFP_Block1/VFP_Block1.c"),
            Object(Matching, "dlls/objects/543/543.c"),
            Object(Matching, "dlls/objects/544/544.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/545/545.c"),
            Object(Matching, "dlls/objects/546_VFPDragHead/VFPDragHead.c"),
            Object(Matching, "dlls/objects/547_VFP_corepla/VFP_corepla.c"),
            Object(Matching, "dlls/objects/548/548.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/549_VFP_flamepo/VFP_flamepo.c"),
            Object(Matching, "dlls/objects/550_VFP_lavapoo/VFP_lavapoo.c"),
            Object(Matching, "dlls/objects/551_VFP_lavasta/VFP_lavasta.c"),
            Object(Matching, "dlls/objects/552/552.c"),
            Object(Matching, "dlls/objects/553_DFP_LevelCo/DFP_LevelCo.c"),
            Object(Matching, "dlls/objects/554_DFP_ObjCrea/DFP_ObjCrea.c"),
            Object(Matching, "dlls/objects/555_DFP_Torch/DFP_Torch.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/556/556.c"),
            Object(Matching, "dlls/objects/557_DFP_seqpoin/DFP_seqpoin.c"),
            Object(Matching, "dlls/objects/558/558.c"),
            Object(Matching, "dlls/objects/559_DFP_floorba/DFP_floorba.c"),
            Object(Matching, "dlls/objects/560_DFP_wallbar/DFP_wallbar.c"),
            Object(Matching, "dlls/objects/561_DFP_ForceAw/DFP_ForceAw.c"),
            Object(Matching, "dlls/objects/562_DFP_RotateP/DFP_RotateP.c"),
            Object(Matching, "dlls/objects/563_DFP_Statue1/DFP_Statue1.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/564_DFP_PerchSw/DFP_PerchSw.c"),
            Object(Matching, "dlls/objects/565_DFP_TargetB/DFP_TargetB.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/566_DFP_LaserBe/laser.c"),
            Object(Matching, "dlls/objects/567_DFPSpPl/DFPSpPl.c"),
            Object(Matching, "dlls/objects/568_LINKA_levco/LINKA_levco.c"),
            Object(Matching, "dlls/objects/569/textblock.c"),
            Object(Matching, "dlls/objects/570_DFP_Platfor/DFP_Platfor.c"),
            Object(Matching, "dlls/objects/571_DFP_Lightni/DFP_Lightni.c"),
            Object(Matching, "dlls/objects/572_DFP_PowerSl/DFP_PowerSl.c"),
            Object(Matching, "dlls/objects/573_DBPointMum/DBPointMum.c"),
            Object(Matching, "dlls/objects/574/574.c"),
            Object(Matching, "dlls/objects/575_DB_egg/DB_egg.c"),
            Object(Matching, "dlls/objects/576_GCRobotBlas/GCRobotBlas.c"),
            Object(Matching, "dlls/objects/577_DrakorEnerg/DrakorEnerg.c"),
            Object(Matching, "dlls/objects/578_DBstealerwo/DBstealerwo.c"),
            Object(Matching, "dlls/objects/579_DBHoleContr/DBHoleContr.c"),
            Object(Matching, "dlls/objects/580/580.c"),
            Object(Matching, "dlls/objects/581/581.c"),
            Object(Matching, "dlls/objects/582/582.c"),
            Object(Matching, "dlls/objects/583/583.c"),
            Object(Matching, "dlls/objects/584/584.c"),
            Object(Matching, "dlls/objects/585/585.c"),
            Object(Matching, "dlls/objects/586/586.c"),
            Object(Matching, "dlls/objects/587/587.c"),
            Object(Matching, "dlls/objects/588_BossDrakor_/BossDrakor_.c"),
            Object(Matching, "dlls/objects/589_BossDrakor/BossDrakor.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(Matching, "dlls/objects/590/590.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/591_KT_RexLevel/KT_RexLevel.c"),
            Object(Matching, "dlls/objects/592_KT_Rex/KT_Rex.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/593_KT_RexFloor/KT_RexFloor.c"),
            Object(Matching, "dlls/objects/594_KT_Lazerwal/KT_Lazerwal.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/595_KT_Lazerlig/KT_Lazerlig.c"),
            Object(Matching, "dlls/objects/596_KT_Fallingr/KT_Fallingr.c"),
            Object(Matching, "dlls/objects/597/597.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/598_DIMSnowHorn/DIMSnowHorn.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/599_DR_EarthWar/DR_EarthWar.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/600_DR_CloudRun/DR_CloudRun.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/601_SB_Cloudrun/SB_Cloudrun.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/602_StaticCamer/StaticCamer.c"),
            Object(Matching, "dlls/objects/603_MSPlantingS/MSPlantingS.c"),
            Object(Matching, "dlls/objects/604/604.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/605_CRCloudRace/CRCloudRace.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/606/606.c"),
            Object(Matching, "dlls/objects/607_CRFuelTank/CRFuelTank.c"),
            Object(Matching, "dlls/objects/608/608.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/609_DR_LaserCan/DR_LaserCan.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/610/610.c"),
            Object(Matching, "dlls/objects/611_GM_MazeWell/GM_MazeWell.c"),
            Object(Matching, "dlls/objects/612/612.c"),
            Object(Matching, "dlls/objects/613_DR_Creator/DR_Creator.c"),
            Object(Matching, "dlls/objects/614_KytesMum/KytesMum.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/615/615.c"),
            Object(Matching, "dlls/objects/616_DR_CageCont/DR_CageCont.c"),
            Object(Matching, "dlls/objects/617_ExplodePlan/ExplodePlan.c"),
            Object(Matching, "dlls/objects/618_DR_Geezer/DR_Geezer.c"),
            Object(Matching, "dlls/objects/619_DR_Chimmey/DR_Chimmey.c"),
            Object(Matching, "dlls/objects/620/620.c"),
            Object(Matching, "dlls/objects/621_DR_Vines/DR_Vines.c"),
            Object(Matching, "dlls/objects/622/622.c"),
            Object(Matching, "dlls/objects/623/623.c"),
            Object(Matching, "dlls/objects/624_DR_Rock/DR_Rock.c"),
            Object(Matching, "dlls/objects/625/625.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/626/626.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/627_FirePipe/FirePipe.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/628_DR_pulley/DR_pulley.c"),
            Object(Matching, "dlls/objects/629_DR_cradle/DR_cradle.c"),
            Object(Matching, "dlls/objects/630/630.c"),
            Object(Matching, "dlls/objects/631_CFWindLiftL/CFWindLiftL.c"),
            Object(Matching, "dlls/objects/632/632.c"),
            Object(Matching, "dlls/objects/633_DR_EnergyDi/DR_EnergyDi.c"),
            Object(Matching, "dlls/objects/634_DR_Collapse/DR_Collapse.c"),
            Object(Matching, "dlls/objects/635/635.c"),
            Object(Matching, "dlls/objects/636_DR_LightBea/DR_LightBea.c"),
            Object(Matching, "dlls/objects/637/637.c"),
            Object(Matching, "dlls/objects/638_DRMusicCont/DRMusicCont.c"),
            Object(Matching, "dlls/objects/639/639.c"),
            Object(Matching, "dlls/objects/640_DR_CloudPer/DR_CloudPer.c"),
            Object(Matching, "dlls/objects/641_DR_EarthCal/DR_EarthCal.c"),
            Object(Matching, "dlls/objects/642_BarrelGener/BarrelGener.c"),
            Object(Matching, "dlls/objects/643_DR_BarrelGr/DR_BarrelGr.c"),
            Object(Matching, "dlls/objects/644/644.c"),
            Object(Matching, "dlls/objects/645_SPShop/SPShop.c"),
            Object(Matching, "dlls/objects/646_SPShopKeepe/SPShopKeepe.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/647_SPScarab/SPScarab.c"),
            Object(Matching, "dlls/objects/648_SPDrape/SPDrape.c"),
            Object(Matching, "dlls/objects/649_SPitembeam/SPitembeam.c"),
            Object(Matching, "dlls/objects/650/650.c"),
            Object(Matching, "dlls/objects/651/651.c", cflags=cflags_dll_noopt_nocse_noprop),
            Object(Matching, "dlls/objects/652_WCBouncyCra/WCBouncyCra.c"),
            Object(Matching, "dlls/objects/653_WCLevelCont/WCLevelCont.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/654_WCBeacon/WCBeacon.c"),
            Object(Matching, "dlls/objects/655_WCPressureS/WCPressureS.c"),
            Object(Matching, "dlls/objects/656_WCPushBlock/WCPushBlock.c", cflags=[*cflags_base, "-opt", "nopeephole,noschedule,nocse,nodeadstore"]),
            Object(Matching, "dlls/objects/657_WCTile/WCTile.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/658_WCTrexStatu/WCTrexStatu.c"),
            Object(Matching, "dlls/objects/659/659.c"),
            Object(Matching, "dlls/objects/660/660.c"),
            Object(Matching, "dlls/objects/661_WCApertureS/WCApertureS.c"),
            Object(Matching, "dlls/objects/662_WCTempleDia/WCTempleDia.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/663_WCTempleBri/WCTempleBri.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/664_WCFloorTile/WCFloorTile.c"),
            Object(Matching, "dlls/objects/665/665.c"),
            Object(Matching, "dlls/objects/666_ARWArwing/ARWArwing.c", cflags=cflags_dll_noopt_noprop_noautoinline),
            Object(Matching, "dlls/objects/667/667.c"),
            Object(Matching, "dlls/objects/668_ARWArwingBo/ARWArwingBo.c"),
            Object(Matching, "dlls/objects/669_ARWArwingGu/ARWArwingGu.c"),
            Object(Matching, "dlls/objects/670/670.c"),
            Object(Matching, "dlls/objects/671_ARWBombColl/ARWBombColl.c"),
            Object(Matching, "dlls/objects/672/672.c", cflags=cflags_dll_noopt_noinline),
            Object(Matching, "dlls/objects/673_ARWLevelCon/ARWLevelCon.c"),
            Object(Matching, "dlls/objects/674_ARWSpeedStr/ARWSpeedStr.c"),
            Object(Matching, "dlls/objects/675/675.c"),
            Object(Matching, "dlls/objects/676/676.c"),
            Object(Matching, "dlls/objects/677_ARWGenerato/ARWGenerato.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/678_ARWSquadron/ARWSquadron.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/679_ARWProximit/ARWProximit.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/680_ARWBlocker/ARWBlocker.c"),
            Object(Matching, "dlls/objects/681/681.c"),
            Object(Matching, "dlls/objects/682_LGTDirectio/LGTDirectio.c"),
            Object(Matching, "dlls/objects/683_LGTProjecte/LGTProjecte.c", cflags=cflags_dll_noopt_nocse),
            Object(Matching, "dlls/objects/684_LGTControlL/LGTControlL.c", cflags=cflags_dll_noopt_level1),
            Object(Matching, "dlls/objects/685/685.c"),
            Object(Matching, "dlls/objects/686_WaterFlowWe/WaterFlowWe.c", extra_cflags=["-opt", "nodeadstore"]),
            Object(Matching, "dlls/objects/687/687.c", cflags=cflags_dll_noopt_nocse_noinline),
            Object(Matching, "dlls/objects/688_BrokenPipe/BrokenPipe.c"),
            Object(Matching, "dlls/objects/689_CmbSrc/CmbSrc.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/690_DustMoteSou/DustMoteSou.c"),
            Object(Matching, "dlls/objects/691/691.c", cflags=cflags_dll_noopt_noprop),
            Object(Matching, "dlls/objects/692_CNTcounter/CNTcounter.c"),
            Object(Matching, "dlls/objects/693_Timer/Timer.c"),
            Object(Matching, "dlls/objects/694_CNThitObjec/CNThitObjec.c"),
            Object(Matching, "dlls/objects/695_MCUpgrade/MCUpgrade.c"),
            Object(Matching, "dlls/objects/696_MCUpgradeMa/MCUpgradeMa.c"),
            Object(Matching, "dlls/objects/697_MCStaffEffe/MCStaffEffe.c"),
            Object(Matching, "dlls/objects/698_MCLightning/MCLightning.c"),
            Object(Matching, "dlls/objects/699_GF_LevelCon/GF_LevelCon.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "dlls/objects/700_Andross/Andross.c", cflags=cflags_dll_noopt_noautoinline_alwaysinline),
            Object(Matching, "dlls/objects/701/701.c", cflags=cflags_dll_noopt),
            Object(Matching, "dlls/objects/702_AndrossBrai/AndrossBrai.c"),
            Object(Matching, "dlls/objects/703_AndrossLigh/AndrossLigh.c"),
            Object(Matching, "dlls/objects/704/704.c"),

            Object(Matching, "main/render.c"),
            Object(Matching, "main/effects_state.c"),
            Object(Matching, "main/envfx.c"),
            Object(Matching, "main/audio.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/audio_sfx.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/audio_stream.c"),
            Object(Matching, "main/camera.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/curves.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/voxmaps.c", extra_cflags=["-inline", "deferred"]),
            Object(Matching, "main/modelEngine.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/pad.c", cflags=[*cflags_dll_noopt_nocse, "-inline", "deferred"]),
            Object(Matching, "main/fileio.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/gametext_data.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/gametext.c", cflags=cflags_dll_noopt_noautoinline_deferred),
            Object(Matching, "main/subtitle.c", cflags=cflags_dll_noopt_level1, extra_cflags=["-inline", "noauto,deferred"]),
            Object(Matching, "main/textrender_drawbox.c"),
            Object(Matching, "main/textrender_boxtex.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/modellight.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/asset_load.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/gameloop.c", cflags=[*cflags_dll_noopt, "-inline", "noauto", "-opt", "nolifetimes"]),
            Object(Matching, "main/vecmath.c"),
            Object(Matching, "main/vecmath_vec3.c"),
            Object(Matching, "main/mm.c", cflags=cflags_dll_noopt_noautoinline_deferred),
            Object(Matching, "main/model.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/object.c"),
            Object(Matching, "main/skystars.c"),
            Object(Matching, "main/objanim.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/objhits.c", cflags=cflags_dll_noopt_noautoinline),
            Object(Matching, "main/objtype.c"),
            Object(Matching, "main/objlib.c"),
            Object(Matching, "main/objexpr.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/objprint.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/objprint_dolphin.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/pi_dolphin.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/pi_videoinit.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/pi_pathsearch.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/zlb.s"),
            Object(Matching, "main/shader_dolphin.c"),
            Object(Matching, "main/boot_logo.c"),
            Object(Matching, "main/rcp_dolphin.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/texture.c", cflags=cflags_dll_noopt_noautoinline_deferred),
            Object(Matching, "main/shader.c", cflags=cflags_dll_noopt_noautoinline_deferred),
            Object(Matching, "main/shadow_dolphin.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/track_dolphin.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/newshadows.c", cflags=cflags_dll_noopt_nodead_noautoinline, extra_cflags=["-inline", "deferred"]),
            Object(Matching, "track/intersect.c", cflags=cflags_dll_noopt_nocse_noautoinline, section_alignments={".data": 4}),
            Object(Matching, "track/intersect_screenmath.c", cflags=cflags_dll_noopt),
            Object(Matching, "track/intersect_mtx44.c", cflags=cflags_dll_noopt),
            Object(Matching, "track/intersect_render.c", cflags=cflags_dll_noopt),
            Object(Matching, "track/intersect_memcard.c", cflags=cflags_dll_noopt),

            Object(Matching, "main/thp/dll_3b.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/thp/n_options.c"),
            Object(Matching, "main/thp/dll_3e.c", section_alignments={".sbss": 4}),
            Object(Matching, "main/thp/attractmovie.c"),
            Object(Matching, "main/thp/picmenu.c", cflags=cflags_dll_noopt_noinline, section_alignments={".sdata2": 4}),
            Object(Matching, "main/thp/THPRead.c"),
            Object(Matching, "main/thp/THPVideoDecode.c"),
            Object(Matching, "main/debug_display.c", cflags=cflags_dll_noopt),
            Object(Matching, "main/obj_movelib.c", cflags=cflags_dll_noopt_nocse),

        ],
    },
]


def link_order_callback(module_id: int, objects: List[str]) -> List[str]:
    if not config.non_matching:
        return objects
    if module_id == 0:
        return objects + ["dummy.c"]
    return objects




config.progress_categories = [
    ProgressCategory("game", "Game Code"),
    ProgressCategory("sdk", "SDK Code"),
    ProgressCategory("third_party", "Third-Party Code"),
]
config.progress_each_module = args.verbose
config.progress_report_args = [
]

if args.mode == "configure":
    generate_build(config)
elif args.mode == "progress":
    calculate_progress(config)
else:
    sys.exit("Unknown mode: " + args.mode)
