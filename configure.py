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
import sys
from pathlib import Path
from typing import Any, Dict, List

from tools.project import (
    Object,
    ProgressCategory,
    ProjectConfig,
    calculate_progress,
    generate_build,
    is_windows,
)

# Game versions
DEFAULT_VERSION = 0
VERSIONS = [
    "GSAE01",  # 0
    "GSAJ01",  # 1
    "GSAP01",  # 2
]

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
    type=str.upper,
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
parser.set_defaults(non_matching=True)
args = parser.parse_args()

config = ProjectConfig()
config.version = str(args.version)
version_num = VERSIONS.index(config.version)

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
config.progress = args.progress
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
config.wibo_tag = "1.0.0"

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

# Optional numeric ID for decomp.me preset
# Can be overridden in libraries or objects
config.scratch_preset_id = None

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

cflags_msl = [
    *cflags_base,
    "-char signed",
    "-use_lmw_stmw on",
    "-str reuse,pool,readonly",
]

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


# Helper function for REL script objects
def Rel(lib_name: str, objects: List[Object]) -> Dict[str, Any]:
    return {
        "lib": lib_name,
        "mw_version": "GC/1.3.2",
        "cflags": cflags_rel,
        "progress_category": "game",
        "objects": objects,
    }


Matching = True                   # Object matches and should be linked
NonMatching = False               # Object does not match and should not be linked
Equivalent = config.non_matching  # Object should be linked when configured with --non-matching


# Object is only matching for specific versions
def MatchingFor(*versions):
    return config.version in versions


config.warn_missing_config = True
config.warn_missing_source = False
config.libs = [
    {
        "lib": "Runtime.PPCEABI.H",
        "mw_version": config.linker_version,
        "cflags": cflags_runtime,
        "progress_category": "sdk",  # str | List[str]
        "objects": [
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__start.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__mem.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/mem_TRK.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__exception.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__va_arg.c"),
            Object(Matching, "Runtime.PPCEABI.H/global_destructor_chain.c"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/runtime.c"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__init_cpp_exceptions.cpp"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/fragment.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/GCN_mem_alloc.c"),
        ],
    },
    DolphinLib(
        "os",
        [
            Object(NonMatching, "dolphin/os/OS.c"),
            Object(NonMatching, "dolphin/os/OSAddress.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSAlarm.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSAlloc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSArena.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSAudioSystem.c"),
            Object(NonMatching, "dolphin/os/OSCache.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSContext.c"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_8032C984.s"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSError.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSExec.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSFont.c", extra_cflags=["-use_lmw_stmw", "on"]),
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
            Object(MatchingFor("GSAE01"), "dolphin/os/OSThread.c", extra_cflags=["-use_lmw_stmw", "on"]),
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
            Object(NonMatching, "dolphin/dvd/dvdlow.c"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_803DC568.s"),
            Object(NonMatching, "dolphin/dvd/dvdfs.c", extra_cflags=["-use_lmw_stmw", "on"]),
            Object(NonMatching, "dolphin/dvd/dvd.c", extra_cflags=["-str", "pool"]),
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
            Object(NonMatching, "dolphin/ar/ar.c"),
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
            Object(NonMatching, "dolphin/ax/AX.c"),
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
            Object(MatchingFor("GSAE01"), "dolphin/si/SIBios.c", extra_cflags=["-inline", "all", "-char", "signed"]),
            Object(MatchingFor("GSAE01"), "dolphin/si/SISamplingRate.c", extra_cflags=["-inline", "all", "-char", "signed"]),
        ],
    ),
    DolphinLib(
        "pad",
        [
            Object(NonMatching, "dolphin/pad/Pad.c"),
            Object(MatchingFor("GSAE01"), "dolphin/pad/Padclamp.c"),
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
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXInit.c"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_803AEA38.s"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_803DE0B8.s"),
            Object(NonMatching, "dolphin/gx/GXFifo.c"),
            Object(NonMatching, "dolphin/gx/GXMisc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXLight.c"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_8032F218.s"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTexture.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXBump.c"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_8032EDD0.s"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXAttr.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXDisplayList.c", extra_cflags=["-sdata", "16"]),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXFrameBuf.c"),
            Object(NonMatching, "dolphin/gx/GXDraw.c"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_8032F618.s"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXPerf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXPixel.c"),
            Object(NonMatching, "dolphin/gx/GXSave.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXStubs.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTev.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTransform.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXGeometry.c"),
            Object(NonMatching, "dolphin/gx/GXVerifRAS.c"),
            Object(NonMatching, "dolphin/gx/GXVerifXF.c"),
            Object(NonMatching, "dolphin/gx/GXVerify.c"),
            Object(NonMatching, "dolphin/gx/GXVert.c"),
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
            Object(NonMatching, "dolphin/axfx/reverb_std.c"),
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
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_803DC588.s"),
            Object(NonMatching, "dolphin/vi/vi.c"),
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
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_803DC630.s"),
            Object(NonMatching, "dolphin/OdemuExi2/DebuggerDriver.c"),
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
            Object(
                MatchingFor("GSAE01"),
                "dolphin/TRK_MINNOW_DOLPHIN/mainloop.c",
                mw_version="GC/1.3.2",
            ),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/nubevent.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/nubinit.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msg.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msgbuf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/serpoll.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/usr_put.c"),
            Object(
                MatchingFor("GSAE01"),
                "dolphin/TRK_MINNOW_DOLPHIN/dispatch.c",
                mw_version="GC/1.3.2",
            ),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_80332EF0.s"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msghndlr.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/support.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mutex_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/notify.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/flush_cache.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mem_TRK.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/targimpl.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targsupp.s"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk.c"),
            Object(MatchingFor("GSAE01"), "main/unknown/autos/placeholder_80332F78.s"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mpc_7xx_603e.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/main_TRK.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk_glue.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targcont.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/target_options.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mslsupp.c"),
            Object(
                MatchingFor("GSAE01"),
                "dolphin/TRK_MINNOW_DOLPHIN/MWTrace.c",
                mw_version="GC/1.2.5n",
                extra_cflags=["-sdata", "8", "-sdata2", "8"],
            ),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/MWCriticalSection_gc.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/main.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/main_gdev.c"),
        ],
    },
    DolphinLib(
        "MSL_C",
        [
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/abort_exit.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/alloc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/ansi_files.c", mw_version="GC/1.3"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/ansi_fp.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/buffer_io.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/direct_io.c", mw_version="GC/1.3", extra_cflags=["-use_lmw_stmw", "on"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/file_io.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/FILE_POS.c", mw_version="GC/1.3"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/mbstring.c", mw_version="GC/1.3.2r", cflags=cflags_msl),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/mem.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/mem_funcs.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/misc_io.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/printf.c", mw_version="GC/1.3", extra_cflags=["-use_lmw_stmw", "on", "-char", "signed"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/string.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/wchar_io.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/ctype.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_copysign.c", mw_version="GC/1.3"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_frexp.c", mw_version="GC/1.3"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_ldexp.c", mw_version="GC/1.3"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_modf.c", mw_version="GC/1.3"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/gamecube.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/uart_console_io_gcn.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/rand.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/math_ppc.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/k_cos.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/k_sin.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_cos.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/e_sqrt.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/e_pow.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/e_atan2.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_tan.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/extras.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/k_tan.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/e_rem_pio2.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_floor.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_sin.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/trigf.c"),
        ],
    ),
    {
        "lib": "main",
        "mw_version": config.linker_version,
        "cflags": cflags_base,
        "progress_category": "game",
        "objects": [
            Object(NonMatching, "main/audio/synth_callback.c"),
            Object(NonMatching, "main/audio/synth_channel.c"),
            Object(NonMatching, "main/audio/synth_handle.c"),
            Object(NonMatching, "main/audio/synth_sequence.c"),
            Object(NonMatching, "main/audio/synth_seq_queue.c"),
            Object(NonMatching, "main/audio/synth_init.c"),
            Object(NonMatching, "main/audio/synth_scale.c"),
            Object(NonMatching, "main/audio/synth_delay.c"),
            Object(NonMatching, "main/audio/synth_control.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80273F4C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80281760.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027641C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027BB84.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80080E28.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_801B1354.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802BB008.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802BB4B0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802791FC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802839B0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80279608.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80278F74.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027ADC4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80279EC0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027A940.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80279AF0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027B41C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027A3E0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_800066E0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8001746C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8002F604.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80080E58.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_801175B4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_801F5184.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80209FE0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8026FD1C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80272EEC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80273608.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802755D0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80275674.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802757AC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027587C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027590C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027C728.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027F724.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802801A8.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80280F28.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802818F8.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80282288.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80282630.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283134.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802835C0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283744.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802836E4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028373C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283BA0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283DA0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283E4C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028429C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028436C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802844BC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284698.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284970.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284BA8.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284CBC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284E78.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80285010.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028521C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802857B0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80295318.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802BBC10.c"),
            Object(NonMatching, "main/objanim.c"),
            Object(NonMatching, "main/lightmap.c"),
            Object(NonMatching, "main/textblock.c"),
            Object(NonMatching, "main/objHitReact.c"),
            Object(NonMatching, "main/expr.c"),
            Object(NonMatching, "main/timer.c"),
            Object(NonMatching, "main/objhits.c"),
            Object(NonMatching, "main/light.c"),
            Object(NonMatching, "main/main.c"),
            Object(NonMatching, "main/objlib.c"),
            Object(NonMatching, "main/objprint.c"),
            Object(NonMatching, "main/objprint_dolphin.c"),
            Object(NonMatching, "main/pi_dolphin.c"),
            Object(NonMatching, "main/rcp_dolphin.c"),
            Object(NonMatching, "main/shader.c"),
            Object(NonMatching, "main/tex_dolphin.c"),
            Object(NonMatching, "main/track_dolphin.c"),
            Object(NonMatching, "main/newshadows.c"),
            Object(NonMatching, "track/intersect.c"),
            Object(NonMatching, "main/maketex.c"),
            Object(NonMatching, "main/expgfx.c"),
            Object(NonMatching, "main/dll/modgfx.c"),
            Object(NonMatching, "main/dll/modelfx.c"),
            Object(NonMatching, "main/dll/dim_partfx.c"),
            Object(NonMatching, "main/dll/df_partfx.c"),
            Object(NonMatching, "main/dll/objfsa.c"),
            Object(NonMatching, "main/dll/curves.c"),
            Object(NonMatching, "main/dll/gameplay.c"),
            Object(NonMatching, "main/dll/foodbag.c"),
            Object(NonMatching, "main/dll/savegame.c"),
            Object(NonMatching, "main/dll/screens.c"),
            Object(NonMatching, "main/dll/CAM/cutCam.c"),
            Object(NonMatching, "main/dll/CAM/camlockon.c"),
            Object(NonMatching, "main/dll/CAM/camTalk.c"),
            Object(NonMatching, "main/dll/CAM/dll_5B.c"),
            Object(NonMatching, "main/dll/CAM/dll_5F.c"),
            Object(NonMatching, "main/dll/CAM/camdrakor.c"),
            Object(NonMatching, "main/dll/CAM/dll_62.c"),
            Object(NonMatching, "main/dll/baddieControl.c"),
            Object(NonMatching, "main/dll/moveLib.c"),
            Object(NonMatching, "main/dll/pickup.c"),
            Object(NonMatching, "main/dll/dll_B5.c"),
            Object(NonMatching, "main/dll/dll_B8.c"),
            Object(NonMatching, "main/dll/FRONT/n_filemenu.c"),
            Object(NonMatching, "main/dll/modanimeflash1.c"),
            Object(NonMatching, "main/dll/dll_66.c"),
            Object(NonMatching, "main/dll/modgfx67.c"),
            Object(NonMatching, "main/dll/dll_68.c"),
            Object(NonMatching, "main/dll/dll_69.c"),
            Object(NonMatching, "main/dll/dll_6A.c"),
            Object(NonMatching, "main/dll/dll_6B.c"),
            Object(NonMatching, "main/dll/dll_6C.c"),
            Object(NonMatching, "main/dll/dll_6D.c"),
            Object(NonMatching, "main/dll/dll_6E.c"),
            Object(NonMatching, "main/dll/dll_6F.c"),
            Object(NonMatching, "main/dll/dll_70.c"),
            Object(NonMatching, "main/dll/dll_71.c"),
            Object(NonMatching, "main/dll/dll_AF.c"),
            Object(NonMatching, "main/dll/dll_72.c"),
            Object(NonMatching, "main/dll/dll_73.c"),
            Object(NonMatching, "main/dll/dll_74.c"),
            Object(NonMatching, "main/dll/dll_64.c"),
            Object(NonMatching, "main/dll/dll_75.c"),
            Object(NonMatching, "main/dll/dll_76.c"),
            Object(NonMatching, "main/dll/dll_77.c"),
            Object(NonMatching, "main/dll/dll_78.c"),
            Object(NonMatching, "main/dll/dll_79.c"),
            Object(NonMatching, "main/dll/dll_7A.c"),
            Object(NonMatching, "main/dll/dll_7B.c"),
            Object(NonMatching, "main/dll/dll_7C.c"),
            Object(NonMatching, "main/dll/dll_7D.c"),
            Object(NonMatching, "main/dll/dll_7E.c"),
            Object(NonMatching, "main/dll/dll_7F.c"),
            Object(NonMatching, "main/dll/dll_80.c"),
            Object(NonMatching, "main/dll/dll_81.c"),
            Object(NonMatching, "main/dll/dll_82.c"),
            Object(NonMatching, "main/dll/dll_83.c"),
            Object(NonMatching, "main/dll/dll_84.c"),
            Object(NonMatching, "main/dll/dll_85.c"),
            Object(NonMatching, "main/dll/modcloudrunner2.c"),
            Object(NonMatching, "main/dll/dll_87.c"),
            Object(NonMatching, "main/dll/dll_88.c"),
            Object(NonMatching, "main/dll/dll_89.c"),
            Object(NonMatching, "main/dll/dll_8A.c"),
            Object(NonMatching, "main/dll/dll_8B.c"),
            Object(NonMatching, "main/dll/dll_8C.c"),
            Object(NonMatching, "main/dll/dll_8D.c"),
            Object(NonMatching, "main/dll/dll_8E.c"),
            Object(NonMatching, "main/dll/dll_8F.c"),
            Object(NonMatching, "main/dll/dll_90.c"),
            Object(NonMatching, "main/dll/dll_91.c"),
            Object(NonMatching, "main/dll/dll_92.c"),
            Object(NonMatching, "main/dll/dll_93.c"),
            Object(NonMatching, "main/dll/dll_94.c"),
            Object(NonMatching, "main/dll/dll_95.c"),
            Object(NonMatching, "main/dll/dll_96.c"),
            Object(NonMatching, "main/dll/dll_97.c"),
            Object(NonMatching, "main/dll/dll_98.c"),
            Object(NonMatching, "main/dll/dll_99.c"),
            Object(NonMatching, "main/dll/dll_9A.c"),
            Object(NonMatching, "main/dll/dll_9B.c"),
            Object(NonMatching, "main/dll/dll_9C.c"),
            Object(NonMatching, "main/dll/dll_9D.c"),
            Object(NonMatching, "main/dll/dll_9E.c"),
            Object(NonMatching, "main/dll/dll_9F.c"),
            Object(NonMatching, "main/dll/dll_A0.c"),
            Object(NonMatching, "main/dll/dll_A1.c"),
            Object(NonMatching, "main/dll/dll_A2.c"),
            Object(NonMatching, "main/dll/dll_A3.c"),
            Object(NonMatching, "main/dll/dll_A4.c"),
            Object(NonMatching, "main/dll/dll_A5.c"),
            Object(NonMatching, "main/dll/dll_A6.c"),
            Object(NonMatching, "main/dll/dll_A7.c"),
            Object(NonMatching, "main/dll/dll_A8.c"),
            Object(NonMatching, "main/dll/dll_A9.c"),
            Object(NonMatching, "main/dll/dll_AA.c"),
            Object(NonMatching, "main/dll/dll_AB.c"),
            Object(NonMatching, "main/dll/dll_AC.c"),
            Object(NonMatching, "main/dll/dll_AD.c"),
            Object(NonMatching, "main/dll/dll_AE.c"),
            Object(NonMatching, "main/dll/dll_B0.c"),
            Object(NonMatching, "main/dll/dll_B1.c"),
            Object(NonMatching, "main/dll/dll_B2.c"),
            Object(NonMatching, "main/dll/dll_B3.c"),
            Object(NonMatching, "main/dll/dll_B4.c"),
            Object(NonMatching, "main/dll/dll_B6.c"),
            Object(NonMatching, "main/dll/dll_B7.c"),
            Object(NonMatching, "main/dll/dll_B9.c"),
            Object(NonMatching, "main/dll/dll_BA.c"),
            Object(NonMatching, "main/dll/dll_BB.c"),
            Object(NonMatching, "main/dll/dll_BC.c"),
            Object(NonMatching, "main/dll/dll_BD.c"),
            Object(NonMatching, "main/dll/dll_BF.c"),
            Object(NonMatching, "main/dll/dll_C4.c"),
            Object(NonMatching, "main/dll/dll_C5.c"),
            Object(NonMatching, "main/dll/dll_C6.c"),
            Object(NonMatching, "main/dll/dll_C0.c"),
            Object(NonMatching, "main/dll/CAM/camcontrol.c"),
            Object(NonMatching, "main/dll/CAM/attention.c"),
            Object(NonMatching, "main/dll/CAM/camslide.c"),
            Object(NonMatching, "main/dll/CAM/firstperson.c"),
            Object(NonMatching, "main/dll/CAM/dll_53.c"),
            Object(NonMatching, "main/dll/CAM/camstatic.c"),
            Object(NonMatching, "main/dll/CAM/pathcam.c"),
            Object(NonMatching, "main/dll/CAM/camshipbattle.c"),
            Object(NonMatching, "main/dll/CAM/camclimb.c"),
            Object(NonMatching, "main/dll/CAM/dll_59.c"),
            Object(NonMatching, "main/dll/CAM/camshipbattle5C.c"),
            Object(NonMatching, "main/dll/CAM/attentioncam.c"),
            Object(NonMatching, "main/dll/CAM/camcannon.c"),
            Object(NonMatching, "main/dll/CAM/dll_60.c"),
            Object(NonMatching, "main/dll/CAM/camDebug.c"),
            Object(NonMatching, "main/dll/projLib.c"),
            Object(NonMatching, "main/dll/FRONT/POST.c"),
            Object(NonMatching, "main/dll/FRONT/n_rareware.c"),
            Object(NonMatching, "main/dll/FRONT/dll_39.c"),
            Object(NonMatching, "main/dll/FRONT/dll_3B.c"),
            Object(NonMatching, "main/dll/FRONT/n_options.c"),
            Object(NonMatching, "main/dll/FRONT/n_pausemenu.c"),
            Object(NonMatching, "main/dll/FRONT/dll_3E.c"),
            Object(NonMatching, "main/dll/FRONT/dll_40.c"),
            Object(NonMatching, "main/dll/FRONT/dll_44.c"),
            Object(NonMatching, "main/dll/FRONT/picmenu.c"),
            Object(NonMatching, "main/dll/FRONT/frontend_control.c"),
            Object(NonMatching, "main/dll/dll_43.c"),
            Object(NonMatching, "main/dll/dll_47.c"),
            Object(NonMatching, "main/dll/dll_36.c"),
            Object(NonMatching, "main/dll/dll_48.c"),
            Object(NonMatching, "main/dll/dll_49.c"),
            Object(NonMatching, "main/dll/dll_4A.c"),
            Object(NonMatching, "main/dll/dll_4B.c"),
            Object(NonMatching, "main/dll/SH/swaphol.c"),
            Object(NonMatching, "main/dll/dll_4E.c"),
            Object(NonMatching, "main/dll/dll_4D.c"),
            Object(NonMatching, "main/dll/debug/prof.c"),
            Object(NonMatching, "main/dll/debug/dimenu.c"),
            Object(NonMatching, "main/dll/tricky.c"),
            Object(NonMatching, "main/dll/maybeTemplate.c"),
            Object(NonMatching, "main/dll/baddie/balloonBaddie.c"),
            Object(NonMatching, "main/dll/baddie/swarmBaddie.c"),
            Object(NonMatching, "main/dll/baddie/wispBaddie.c"),
            Object(NonMatching, "main/dll/baddie/baby_snowworm.c"),
            Object(NonMatching, "main/dll/baddie/wall_crawler.c"),
            Object(NonMatching, "main/dll/baddie/dll_DB.c"),
            Object(NonMatching, "main/dll/baddie/dll_DA.c"),
            Object(NonMatching, "main/dll/baddie/TumbleweedBush.c"),
            Object(NonMatching, "main/dll/baddie/Tumbleweed.c"),
            Object(NonMatching, "main/dll/baddie/skeetla.c"),
            Object(NonMatching, "main/dll/baddie/dll_DF.c"),
            Object(NonMatching, "main/dll/baddie/MMP_cratercritter.c"),
            Object(NonMatching, "main/dll/baddie/MMP_critterspit.c"),
            Object(NonMatching, "main/dll/dll_E2.c"),
            Object(NonMatching, "main/dll/dll_D1.c"),
            Object(NonMatching, "main/dll/animobjD2.c"),
            Object(NonMatching, "main/dll/dll_D3.c"),
            Object(NonMatching, "main/dll/weaponE6.c"),
            Object(NonMatching, "main/dll/cannon.c"),
            Object(NonMatching, "main/dll/cannonball.c"),
            Object(NonMatching, "main/dll/grenade.c"),
            Object(NonMatching, "main/dll/collectable.c"),
            Object(NonMatching, "main/dll/sidekickToy.c"),
            Object(NonMatching, "main/dll/projswitch.c"),
            Object(NonMatching, "main/dll/pressureSwitch.c"),
            Object(NonMatching, "main/dll/seqObj.c"),
            Object(NonMatching, "main/dll/newSeqObj.c"),
            Object(NonMatching, "main/dll/seqObj11D.c"),
            Object(NonMatching, "main/dll/seqObj11E.c"),
            Object(NonMatching, "main/dll/magicPlant.c"),
            Object(NonMatching, "main/dll/dll_10A.c"),
            Object(NonMatching, "main/dll/dll_10B.c"),
            Object(NonMatching, "main/dll/duster.c"),
            Object(NonMatching, "main/dll/smallbasket.c"),
            Object(NonMatching, "main/dll/mediumbasket.c"),
            Object(NonMatching, "main/dll/scarab.c"),
            Object(NonMatching, "main/dll/barrel.c"),
            Object(NonMatching, "main/dll/ladders.c"),
            Object(NonMatching, "main/dll/waterfallControl.c"),
            Object(NonMatching, "main/dll/backpack.c"),
            Object(NonMatching, "main/dll/landedArwing.c"),
            Object(NonMatching, "main/dll/staffAction.c"),
            Object(NonMatching, "main/dll/treasurechest.c"),
            Object(NonMatching, "main/dll/dll_131.c"),
            Object(NonMatching, "main/dll/dll_134.c"),
            Object(NonMatching, "main/dll/campfire.c"),
            Object(NonMatching, "main/dll/dll_13B.c"),
            Object(NonMatching, "main/dll/dll_13C.c"),
            Object(NonMatching, "main/dll/genprops.c"),
            Object(NonMatching, "main/dll/gfxEmit.c"),
            Object(NonMatching, "main/dll/dll_13F.c"),
            Object(NonMatching, "main/dll/dll_141.c"),
            Object(NonMatching, "main/dll/dll_138.c"),
            Object(NonMatching, "main/dll/transporter.c"),
            Object(NonMatching, "main/dll/autoTransporter.c"),
            Object(NonMatching, "main/dll/dll_13E.c"),
            Object(NonMatching, "main/dll/dll_140.c"),
            Object(NonMatching, "main/dll/tFrameAnimator.c"),
            Object(NonMatching, "main/dll/screenOverlay.c"),
            Object(NonMatching, "main/dll/dll_145.c"),
            Object(NonMatching, "main/dll/texScroll.c"),
            Object(NonMatching, "main/dll/dll_147.c"),
            Object(NonMatching, "main/dll/dll_148.c"),
            Object(NonMatching, "main/dll/alphaanim.c"),
            Object(NonMatching, "main/dll/groundAnimator.c"),
            Object(NonMatching, "main/dll/crackanim.c"),
            Object(NonMatching, "main/dll/dll_14C.c"),
            Object(NonMatching, "main/dll/dll_14D.c"),
            Object(NonMatching, "main/dll/dll_14F.c"),
            Object(NonMatching, "main/dll/dll_150.c"),
            Object(NonMatching, "main/dll/exploder.c"),
            Object(NonMatching, "main/dll/dll_152.c"),
            Object(NonMatching, "main/dll/dll_153.c"),
            Object(NonMatching, "main/dll/dll_159.c"),
            Object(NonMatching, "main/dll/dll_15A.c"),
            Object(NonMatching, "main/dll/dll_15B.c"),
            Object(NonMatching, "main/dll/CF/CFguardian.c"),
            Object(NonMatching, "main/dll/CF/windlift.c"),
            Object(NonMatching, "main/dll/CF/CFcrystal.c"),
            Object(NonMatching, "main/dll/CF/CFBaby.c"),
            Object(NonMatching, "main/dll/CF/CFPrisonGuard.c"),
            Object(NonMatching, "main/dll/CF/dll_163.c"),
            Object(NonMatching, "main/dll/CF/dll_164.c"),
            Object(NonMatching, "main/dll/CF/dll_165.c"),
            Object(NonMatching, "main/dll/CF/dll_166.c"),
            Object(NonMatching, "main/dll/CF/CFtoggleswitch.c"),
            Object(NonMatching, "main/dll/CF/CFforcecontrol.c"),
            Object(NonMatching, "main/dll/CF/treasureRelated0177.c"),
            Object(NonMatching, "main/dll/CF/dll_179.c"),
            Object(NonMatching, "main/dll/CF/dll_17A.c"),
            Object(NonMatching, "main/dll/CF/CFlevelControl.c"),
            Object(NonMatching, "main/dll/CF/CFTreasSharpy.c"),
            Object(NonMatching, "main/dll/CF/CFchuckobj.c"),
            Object(NonMatching, "main/dll/CF/CFwalltorch.c"),
            Object(NonMatching, "main/dll/dll_17F.c"),
            Object(NonMatching, "main/dll/dll_180.c"),
            Object(NonMatching, "main/dll/holoPoint.c"),
            Object(NonMatching, "main/dll/dll_182.c"),
            Object(NonMatching, "main/dll/MMP/mmp_barrel.c"),
            Object(NonMatching, "main/dll/MMP/mmp_levelcontrol.c"),
            Object(NonMatching, "main/dll/MMP/MMP_asteroid.c"),
            Object(NonMatching, "main/dll/MMP/MMP_moonrock.c"),
            Object(NonMatching, "main/dll/MMP/MMP_gyservent.c"),
            Object(NonMatching, "main/dll/DR/hightop.c"),
            Object(NonMatching, "main/dll/DR/sandwormBoss.c"),
            Object(NonMatching, "main/dll/DR/gasvent.c"),
            Object(NonMatching, "main/dll/DR/cannontargetControl.c"),
            Object(NonMatching, "main/dll/DR/gasventControl.c"),
            Object(NonMatching, "main/dll/IM/IMicicle.c"),
            Object(NonMatching, "main/dll/IM/IMspacecraft.c"),
            Object(NonMatching, "main/dll/DIM/DIMlavaball.c"),
            Object(NonMatching, "main/dll/DIM/DIMlogfire.c"),
            Object(NonMatching, "main/dll/DIM/DIMsnowball.c"),
            Object(NonMatching, "main/dll/DIM/DIMboulder.c"),
            Object(NonMatching, "main/dll/DIM/DIMcannon.c"),
            Object(NonMatching, "main/dll/DIM/DIMlavasmash.c"),
            Object(NonMatching, "main/dll/DIM/DIMExplosion.c"),
            Object(NonMatching, "main/dll/DIM/DIMwooddoor.c"),
            Object(NonMatching, "main/dll/DIM/DIMlevcontrol.c"),
            Object(NonMatching, "main/dll/DIM/DIM2conveyor.c"),
            Object(NonMatching, "main/dll/DIM/DIM2flameburst.c"),
            Object(NonMatching, "main/dll/DIM/DIM2snowball.c"),
            Object(NonMatching, "main/dll/DIM/DIM2projrock.c"),
            Object(NonMatching, "main/dll/DIM/DIM2lift.c"),
            Object(NonMatching, "main/dll/DIM/DIM2icicle.c"),
            Object(NonMatching, "main/dll/DIM/DIMboss.c"),
            Object(NonMatching, "main/dll/DIM/DIMbosstonsil.c"),
            Object(NonMatching, "main/dll/DIM/dll_223.c"),
            Object(NonMatching, "main/dll/DIM/DIMbossspit.c"),
            Object(NonMatching, "main/dll/dll_224.c"),
            Object(NonMatching, "main/dll/dll_226.c"),
            Object(NonMatching, "main/dll/dll_227.c"),
            Object(NonMatching, "main/dll/riverFlowRelated018D.c"),
            Object(NonMatching, "main/dll/dll_18E.c"),
            Object(NonMatching, "main/dll/DF/rope.c"),
            Object(NonMatching, "main/dll/DF/DFcradle.c"),
            Object(NonMatching, "main/dll/DF/DFpulley.c"),
            Object(NonMatching, "main/dll/DF/DFbarrel.c"),
            Object(NonMatching, "main/dll/DF/DFbarrelanim.c"),
            Object(NonMatching, "main/dll/DF/dll_194.c"),
            Object(NonMatching, "main/dll/DF/dll_195.c"),
            Object(NonMatching, "main/dll/DF/dll_196.c"),
            Object(NonMatching, "main/dll/DF/DFmole.c"),
            Object(NonMatching, "main/dll/DF/DFwhirlpool.c"),
            Object(NonMatching, "main/dll/DF/dll_198.c"),
            Object(NonMatching, "main/dll/DF/dll_199.c"),
            Object(NonMatching, "main/dll/DF/DFlantern.c"),
            Object(NonMatching, "main/dll/dll_19C.c"),
            Object(NonMatching, "main/dll/dll_19E.c"),
            Object(NonMatching, "main/dll/creator19D.c"),
            Object(NonMatching, "main/dll/laser19F.c"),
            Object(NonMatching, "main/dll/mmshrine/shrine.c"),
            Object(NonMatching, "main/dll/mmshrine/animobj1C0.c"),
            Object(NonMatching, "main/dll/mmshrine/torch1C1.c"),
            Object(NonMatching, "main/dll/mmshrine/shrine1C2.c"),
            Object(NonMatching, "main/dll/creator1C4.c"),
            Object(NonMatching, "main/dll/dll_1C5.c"),
            Object(NonMatching, "main/dll/creator1C6.c"),
            Object(NonMatching, "main/dll/scene1C7.c"),
            Object(NonMatching, "main/dll/flybaddie.c"),
            Object(NonMatching, "main/dll/colrise.c"),
            Object(NonMatching, "main/dll/cup1C3.c"),
            Object(NonMatching, "main/dll/dll_1CA.c"),
            Object(NonMatching, "main/dll/symbol.c"),
            Object(NonMatching, "main/dll/dll_1CC.c"),
            Object(NonMatching, "main/dll/torch1CD.c"),
            Object(NonMatching, "main/dll/shrine1CE.c"),
            Object(NonMatching, "main/dll/creator1CF.c"),
            Object(NonMatching, "main/dll/dll_1D0.c"),
            Object(NonMatching, "main/dll/dll_1D1.c"),
            Object(NonMatching, "main/dll/ped.c"),
            Object(NonMatching, "main/dll/dll_1D3.c"),
            Object(NonMatching, "main/dll/creator1D4.c"),
            Object(NonMatching, "main/dll/dll_1D5.c"),
            Object(NonMatching, "main/dll/creator1D6.c"),
            Object(NonMatching, "main/dll/flybaddie1D7.c"),
            Object(NonMatching, "main/dll/projball1D8.c"),
            Object(NonMatching, "main/dll/torch1D9.c"),
            Object(NonMatching, "main/dll/NW/NWsfx.c"),
            Object(NonMatching, "main/dll/NW/dll_1DB.c"),
            Object(NonMatching, "main/dll/NW/dll_1DC.c"),
            Object(NonMatching, "main/dll/NW/NWmammoth.c"),
            Object(NonMatching, "main/dll/NW/NWtricky.c"),
            Object(NonMatching, "main/dll/dll_1DF.c"),
            Object(NonMatching, "main/dll/dll_1E0.c"),
            Object(NonMatching, "main/dll/dll_1E1.c"),
            Object(NonMatching, "main/dll/dll_1E2.c"),
            Object(NonMatching, "main/dll/SH/SHmushroom.c"),
            Object(NonMatching, "main/dll/SH/SHkillermushroom.c"),
            Object(NonMatching, "main/dll/SH/SHrocketmushroom.c"),
            Object(NonMatching, "main/dll/SH/SHspore.c"),
            Object(NonMatching, "main/dll/SH/dll_1E7.c"),
            Object(NonMatching, "main/dll/SH/lily.c"),
            Object(NonMatching, "main/dll/SH/dll_1E8.c"),
            Object(NonMatching, "main/dll/SH/SHthorntail.c"),
            Object(NonMatching, "main/dll/SH/SHroot.c"),
            Object(NonMatching, "main/dll/SC/SClevelcontrol.c"),
            Object(NonMatching, "main/dll/SC/SClightfoot.c"),
            Object(NonMatching, "main/dll/SC/SCchieflightfoot.c"),
            Object(NonMatching, "main/dll/SC/SClantern.c"),
            Object(NonMatching, "main/dll/SC/SCcollectables.c"),
            Object(NonMatching, "main/dll/SC/SCanimobj.c"),
            Object(NonMatching, "main/dll/SC/SCtotemlogpuz.c"),
            Object(NonMatching, "main/dll/SC/SCtotembondpuz.c"),
            Object(NonMatching, "main/dll/SC/SCtotemstrength.c"),
            Object(NonMatching, "main/dll/brokecannon.c"),
            Object(NonMatching, "main/dll/SP/SPshop.c"),
            Object(NonMatching, "main/dll/SP/SPshopkeeper.c"),
            Object(NonMatching, "main/dll/SP/SPdrape.c"),
            Object(NonMatching, "main/dll/IM/IMsnowbike.c"),
            Object(NonMatching, "main/dll/DR/DRearthwalk.c"),
            Object(NonMatching, "main/dll/CR/CRsnowbike.c"),
            Object(NonMatching, "main/dll/DR/DRcloudrunner.c"),
            Object(NonMatching, "main/dll/WM/deaddino.c"),
            Object(NonMatching, "main/dll/WM/WMlevcontrol.c"),
            Object(NonMatching, "main/dll/WM/WMcrystal.c"),
            Object(NonMatching, "main/dll/VF/VFlevcontrol.c"),
            Object(NonMatching, "main/dll/VF/platform1.c"),
            Object(NonMatching, "main/dll/VF/draghead.c"),
            Object(NonMatching, "main/dll/VF/lavaflow.c"),
            Object(NonMatching, "main/dll/DB/DBrockfall.c"),
            Object(NonMatching, "main/dll/DB/DBpointmum.c"),
            Object(NonMatching, "main/dll/DB/DBwaterflow.c"),
            Object(NonMatching, "main/dll/DB/DBlightgo.c"),
            Object(NonMatching, "main/dll/DB/DBbullet.c"),
            Object(NonMatching, "main/dll/DB/DBprotection.c"),
            Object(NonMatching, "main/dll/DB/DBdustgeezer.c"),
            Object(NonMatching, "main/dll/DB/DBbonedust.c"),
            Object(NonMatching, "main/dll/DB/DBstealerworm.c"),
            Object(NonMatching, "main/dll/CR/CRsnowClaw.c"),
            Object(NonMatching, "main/dll/CR/CRfueltank.c"),
            Object(NonMatching, "main/dll/TREX/TREX_levelcontrol.c"),
            Object(NonMatching, "main/dll/TREX/TREX_trex.c"),
            Object(NonMatching, "main/dll/TREX/TREX_Lazerwall.c"),
            Object(NonMatching, "main/dll/DR/DRlaserturret.c"),
            Object(NonMatching, "main/dll/DR/DRpushcart.c"),
            Object(NonMatching, "main/dll/DR/DRCloudball.c"),
            Object(NonMatching, "main/dll/DR/DRsimplehuman.c"),
            Object(NonMatching, "main/dll/DR/DRyoutube.c"),
            Object(NonMatching, "main/dll/DR/DRexplodeDoor.c"),
            Object(NonMatching, "main/dll/DR/DRcloudcage.c"),
            Object(NonMatching, "main/dll/DR/DRshackle.c"),
            Object(NonMatching, "main/dll/DR/DRhightop.c"),
            Object(NonMatching, "main/dll/DR/DRpickup.c"),
            Object(NonMatching, "main/dll/DR/DRcradle.c"),
            Object(NonMatching, "main/dll/DR/DRpulley.c"),
            Object(NonMatching, "main/dll/DR/DRhalolight.c"),
            Object(NonMatching, "main/dll/DR/DRbarrelplace.c"),
            Object(NonMatching, "main/dll/BW/BWalphaanim.c"),
            Object(NonMatching, "main/dll/WC/WCpushblock.c"),
            Object(NonMatching, "main/dll/WC/WClevcontrol.c"),
            Object(NonMatching, "main/dll/WC/WCbeacon.c"),
            Object(NonMatching, "main/dll/WC/WCpressureSwitch.c"),
            Object(NonMatching, "main/dll/WC/WCdial.c"),
            Object(NonMatching, "main/dll/WC/WClaser.c"),
            Object(NonMatching, "main/dll/WC/WCfloortile.c"),
            Object(NonMatching, "main/dll/ARW/ARWarwingattachment.c"),
            Object(NonMatching, "main/dll/LGT/LGTpointlight.c"),
            Object(NonMatching, "main/dll/LGT/LGTdirectionallight.c"),
            Object(NonMatching, "main/dll/LGT/LGTprojectedlight.c"),
            Object(NonMatching, "main/dll/LGT/LGTcontrollight.c"),
            Object(NonMatching, "main/dll/boulder.c"),
            Object(NonMatching, "main/dll/anim.c"),
            Object(NonMatching, "main/dll/baddie/chuka.c"),
            Object(NonMatching, "main/dll/baddie/chukachuck.c"),
            Object(NonMatching, "main/dll/tesla.c"),
            Object(NonMatching, "main/dll/dll_EC.c"),
            Object(NonMatching, "main/dll/TrickyCurve.c"),
            Object(NonMatching, "main/dll/sfxplayer.c"),
            Object(NonMatching, "main/dll/crate.c"),
            Object(NonMatching, "main/dll/crate2.c"),
            Object(NonMatching, "main/dll/door.c"),
            Object(NonMatching, "main/dll/fruit.c"),
            Object(NonMatching, "main/dll/zBomb.c"),
            Object(NonMatching, "main/dll/CF/laser_unsupported.c"),
            Object(NonMatching, "main/dll/CF/laserObj.c"),
            Object(NonMatching, "main/dll/fire.c"),
            Object(NonMatching, "main/platform1.c"),
            Object(NonMatching, "main/dfplightni.c"),
            Object(NonMatching, "main/dll/CF/laser.c"),
            Object(NonMatching, "main/dfppowersl.c"),
            Object(NonMatching, "main/worldasteroids.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8020C5EC.c"),
            Object(NonMatching, "main/worldplanet.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8020C9CC.c"),
            Object(NonMatching, "main/crcloudrace.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80210BE8.c"),
            Object(NonMatching, "main/spellstone.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80210E8C.c"),
            Object(NonMatching, "main/crfueltank.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802110F8.c"),
            Object(NonMatching, "main/proximitymine.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802113F8.c"),
            Object(NonMatching, "main/proximitymine_init.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80211C24.c"),
            Object(NonMatching, "main/dll/firepipe.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80220608.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8026CBEC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8026DFE4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8026E848.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8026F134.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8026FD94.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80271BFC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027280C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80272F0C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802736D4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80273F50.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802755E0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80275684.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802757BC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027588C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027591C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802765AC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80279018.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802792F8.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027979C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80279D30.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027A2FC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027A710.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027AC80.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027B038.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027B53C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027BB90.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027CAF4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8027F8B0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028026C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028116C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802817A8.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80281A9C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80282594.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802827D4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283488.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028364C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802836F4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802839F4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283BF0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283E10.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80283FA0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802842C4.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284410.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_802844C0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028479C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284988.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284BAC.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80284EF0.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_8028503C.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80285220.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_80285B64.c"),
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
