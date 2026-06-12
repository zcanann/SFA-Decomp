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

cflags_runtime_125 = [flag for flag in cflags_runtime if flag != "-gccinc"]

# Game/DLL TUs the original build compiled with the scheduler and peephole
# passes off (a per-TU compiler setting, not a per-function one).
cflags_dll_noopt = [
    *cflags_base,
    "-opt", "nopeephole,noschedule",
]

cflags_dll_nosched = [
    *cflags_base,
    "-opt", "noschedule",
]

cflags_dll_nopeep = [
    *cflags_base,
    "-opt", "nopeephole",
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
            Object(
                MatchingFor("GSAE01"),
                "Runtime.PPCEABI.H/__start.c",
                mw_version="GC/1.2.5n",
                cflags=cflags_runtime_125,
            ),
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
            Object(NonMatching, "main/unknown/autos/placeholder_8032C984.c"),
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
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvdlow.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/DVDLowFirstRead.c"),
            Object(MatchingFor("GSAE01"), "dolphin/dvd/dvdfs.c", extra_cflags=["-use_lmw_stmw", "on"]),
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
            Object(MatchingFor("GSAE01"), "dolphin/si/SIBios.c", extra_cflags=["-inline", "all", "-char", "signed"]),
            Object(MatchingFor("GSAE01"), "dolphin/si/SISamplingRate.c", extra_cflags=["-inline", "all", "-char", "signed"]),
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
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTextureTables.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXTexture.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXBump.c"),
            Object(MatchingFor("GSAE01"), "main/audio/mcmd_data.c", progress_category="game"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXAttr.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXDisplayList.c", extra_cflags=["-sdata", "16"]),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXFrameBuf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXDrawTorusRadius.c"),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXDraw.c", extra_cflags=["-fp_contract", "off"]),
            Object(MatchingFor("GSAE01"), "dolphin/gx/GXDrawTorusAngle.c"),
            Object(MatchingFor("GSAE01"), "main/audio/adsr_data.c", progress_category="game"),
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
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msghndlr_tables.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/msghndlr.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/support.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mutex_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/notify.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/flush_cache.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mem_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targimpl.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targimpl_tables.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targsupp.s"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mpc_7xx_603e_tables.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mpc_7xx_603e.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/main_TRK.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk_glue.c"),
            Object(NonMatching, "main/unknown/autos/placeholder_803D8888.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targcont.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/target_options.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/mslsupp.c"),
            Object(
                MatchingFor("GSAE01"),
                "dolphin/TRK_MINNOW_DOLPHIN/MWTrace.c",
                mw_version="GC/1.2.5n",
                extra_cflags=["-sdata", "8", "-sdata2", "8", "-schedule", "off"],
            ),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/MWCriticalSection_gc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/main.c", progress_category="sdk"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/CircleBuffer.c", progress_category="sdk"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/main_gdev.c", progress_category="sdk"),
        ],
    },
    DolphinLib(
        "MSL_C",
        [
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/abort_exit.c", mw_version="GC/1.3"),
            Object(
                MatchingFor("GSAE01"),
                "dolphin/MSL_C/PPCEABI/bare/H/alloc.c",
                mw_version="GC/1.3",
                cflags=cflags_msl,
                extra_cflags=["-common", "off", "-inline", "auto,deferred"],
            ),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/ansi_files.c", mw_version="GC/1.3"),
            Object(
                MatchingFor("GSAE01"),
                "dolphin/MSL_C/PPCEABI/bare/H/ansi_fp.c",
                mw_version="GC/1.3",
                extra_cflags=[
                    "-inline",
                    "all",
                    "-inline",
                    "auto,deferred",
                    "-use_lmw_stmw",
                    "on",
                    "-char",
                    "signed",
                    "-str",
                    "pool,readonly",
                ],
            ),
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
            Object(MatchingFor("GSAE01"), "dolphin/base/PPCArch_weak.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/ctype_funcs.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/uart_console_io_gcn.c", mw_version="GC/1.2.5"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/hyperbolicsf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/floorf.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/rand.c", mw_version="GC/1.1", extra_cflags=["-O0"]),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/math_ppc.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_cos.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/s_atan.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/e_acos.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/e_fmod.c"),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/exponentialsf.c",
                mw_version="GC/1.1",
                extra_cflags=["-O3,p", "-opt", "nopeephole", "-sdata", "0"],
            ),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/extras.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/k_rem_pio2.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_acos.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_atan2.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_fmod.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_pow.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/w_sqrt.c"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/common_float_tables.c", mw_version="GC/1.3"),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/trigf.c", mw_version="GC/1.2.5"),
        ],
    ),
    {
        "lib": "main",
        "mw_version": "GC/2.0",
        "cflags": cflags_base,
        "progress_category": "game",
        "objects": [
            Object(MatchingFor("GSAE01"), "main/audio/synth_constants.c"),
            Object(NonMatching, "main/audio/synth_callback.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_channel.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_handle.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_sequence.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_seq_queue.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_init.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_delay.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_control.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/snd_synth_api.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/mcmd_volume.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/voice_prio.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/vid_init.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/vsample_alloc.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/voice_manage.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/adsr_handle.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/voice_alloc.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/vsample_update.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/voice_conv.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/render.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/audio.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/camera.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/curves.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/voxmaps.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/modelEngine.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/pad.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/fileio.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/gametext.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/textrender.c"),
            Object(NonMatching, "main/modellight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/gameloop.c"),
            Object(NonMatching, "main/vecmath.c"),
            Object(NonMatching, "main/mm.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/model.c"),
            Object(NonMatching, "main/object.c"),
            Object(NonMatching, "main/objseq.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/sky.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/newclouds.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "dolphin/MSL_C/PPCEABI/bare/H/gamecube.c", progress_category="sdk"),
            Object(NonMatching, "main/dll/cloudaction.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/waterfx.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/viewfinder.c"),
            Object(NonMatching, "main/dll/objfx.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/expgfxresource.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/audio_decode_thread.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WM/dll_020B_firefly.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "main/dll/WM/dll_020C_wmspiritplace.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "main/dll/WM/dll_020D_wmseqpoint.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WM/dll_020E_wmsun.c"),
            Object(NonMatching, "main/dll/WM/dll_020F_wmspiritset.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WM/dll_0210_wmplanets.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WM/dll_0211_wmwallcrawler.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "main/dll/WM/dll_0215_wmnewcrystal.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_0216_vfplevelcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_0217_vfpobjcreator.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_0218_vfpminifire.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_0219.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_021A_vfpstatueball.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_021B.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_021C_vfpladders.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_021D_vfplift.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/dll_021E_vfpblock1.c"),
            Object(NonMatching, "main/dll/DR/dll_024D_bossdrakor.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_024E_drakord_thornbush.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/audio/snd3d.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/inp_midi_set.c", mw_version="GC/1.2.5n"),
            Object(MatchingFor("GSAE01"), "main/audio/inp_value.c", mw_version="GC/1.2.5n", extra_cflags=["-Cpp_exceptions", "on"]),
            Object(NonMatching, "main/audio/inp_voice_aux.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_init.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_adsr.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_voice_params.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_voice_start.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_input.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_aram.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_samplemem.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/dll/player.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_01B5_lightfoot.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/dll_0256_dimsnowhorn1.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/dll_01D9_dim2prisonmammoth.c"),
            Object(NonMatching, "main/dll/DR/dll_0077_DR_EarthWarrior.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0078_DR_CloudRunner.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/objanim.c"),
            Object(NonMatching, "main/lightmap.c"),
            Object(NonMatching, "main/textblock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/objHitReact.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/objhits.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/light.c"),
            Object(NonMatching, "main/main.c"),
            Object(NonMatching, "main/objlib.c"),
            Object(NonMatching, "main/objprint.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/objprint_dolphin.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/pi_dolphin.c"),
            Object(NonMatching, "main/rcp_dolphin.c"),
            Object(NonMatching, "main/shader.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/tex_dolphin.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/track_dolphin.c"),
            Object(NonMatching, "main/newshadows.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "track/intersect.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/maketex.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/expgfx.c"),
            Object(NonMatching, "main/dll/modgfx.c"),
            Object(NonMatching, "main/dll/modelfx.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dim_partfx.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/df_partfx.c"),
            Object(NonMatching, "main/dll/objfsa.c"),
            Object(NonMatching, "main/dll/curves.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/gameplay.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/foodbag.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/savegame.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/screens.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/cutCam.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/dll_0042_unk.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/camlockon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/dll_0043_unk.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/camTalk.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/dll_5B.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/dll_5F.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/camdrakor.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/dll_62.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddieControl.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/moveLib.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/pickup.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_B8.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/n_filemenu.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/modanimeflash1.c"),
            Object(NonMatching, "main/dll/dll_66.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00B4_projenergise1.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00B5_projenergise2.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00B2_projrobotfire.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00B6_projsquirt1.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00B7_projship1.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00BB_projwallpower.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00BC_projquakeshock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00BD_projsunshock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00BE_projtesla.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00BF_projcore1.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00C0_projcore2.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00C1_projcore3.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_00C2_projdfp1r.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_8B.c"),
            Object(NonMatching, "main/dll/dll_8C.c"),
            Object(NonMatching, "main/dll/dll_8D.c"),
            Object(NonMatching, "main/dll/dll_8F.c"),
            Object(NonMatching, "main/dll/dll_90.c"),
            Object(NonMatching, "main/dll/dll_92.c"),
            Object(NonMatching, "main/dll/dll_93.c"),
            Object(NonMatching, "main/dll/dll_95.c"),
            Object(NonMatching, "main/dll/dll_96.c"),
            Object(NonMatching, "main/dll/dll_98.c"),
            Object(NonMatching, "main/dll/dll_99.c"),
            Object(NonMatching, "main/dll/dll_9B.c"),
            Object(NonMatching, "main/dll/dll_9C.c"),
            Object(NonMatching, "main/dll/dll_9E.c"),
            Object(NonMatching, "main/dll/dll_9F.c"),
            Object(NonMatching, "main/dll/dll_A1.c"),
            Object(NonMatching, "main/dll/dll_A2.c"),
            Object(NonMatching, "main/dll/dll_A4.c"),
            Object(NonMatching, "main/dll/dll_A5.c"),
            Object(NonMatching, "main/dll/dll_A6.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_A7.c"),
            Object(NonMatching, "main/dll/dll_A8.c"),
            Object(NonMatching, "main/dll/dll_AA.c"),
            Object(NonMatching, "main/dll/dll_AB.c"),
            Object(NonMatching, "main/dll/dll_AD.c"),
            Object(NonMatching, "main/dll/dll_AE.c"),
            Object(NonMatching, "main/dll/dll_B1.c"),
            Object(NonMatching, "main/dll/dll_B2.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_B3.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_B4.c", cflags=cflags_dll_nosched),
            Object(NonMatching, "main/dll/dll_B6.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_B7.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_BB.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_BC.c", cflags=cflags_dll_nosched),
            Object(NonMatching, "main/dll/dll_BD.c"),
            Object(NonMatching, "main/dll/dll_BF.c"),
            Object(NonMatching, "main/dll/dll_C4.c"),
            Object(NonMatching, "main/dll/CAM/camcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/dll_53.c"),
            Object(NonMatching, "main/dll/CAM/pathcam.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/camshipbattle5C.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/attentioncam.c"),
            Object(NonMatching, "main/dll/CAM/camcannon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CAM/dll_60.c"),
            Object(NonMatching, "main/dll/CAM/camDebug.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/projLib.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/POST.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/n_rareware.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/dll_39.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/dll_3B.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/n_options.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/n_pausemenu.c"),
            Object(NonMatching, "main/dll/FRONT/dll_3E.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/dll_40.c"),
            Object(NonMatching, "main/dll/FRONT/dll_44.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/picmenu.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/FRONT/frontend_control.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_43.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_47.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_0036_entersavenamescreen.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_48.c"),
            Object(NonMatching, "main/dll/dll_49.c"),
            Object(NonMatching, "main/dll/dll_4B.c"),
            Object(NonMatching, "main/dll/SH/swaphol.c"),
            Object(NonMatching, "main/dll/dll_4E.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_4D.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/debug/prof.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/debug/dimenu.c"),
            Object(NonMatching, "main/dll/tricky.c"),
            Object(NonMatching, "main/dll/maybeTemplate.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/balloonBaddie.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/swarmBaddie.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/wispBaddie.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/baby_snowworm.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/wall_crawler.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/dll_DB.c"),
            Object(NonMatching, "main/dll/baddie/dll_DA.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/TumbleweedBush.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/Tumbleweed.c"),
            Object(NonMatching, "main/dll/baddie/skeetla.c"),
            Object(NonMatching, "main/dll/baddie/dll_DF.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/MMP_cratercritter.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/MMP_critterspit.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/staff.c"),
            Object(NonMatching, "main/dll/tumbleweedbush.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/animobjD2.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_D3.c"),
            Object(NonMatching, "main/dll/weaponE6.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cannon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cannonball.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/grenade.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/collectable.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/sidekickToy.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/pressureSwitch.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/seqObj.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/newSeqObj.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/seqObj11D.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/seqObj11E.c"),
            Object(NonMatching, "main/dll/magicPlant.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/fall_ladders.c"),
            Object(NonMatching, "main/dll/fireflyLantern.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/duster.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/smallbasket.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mediumbasket.c"),
            Object(NonMatching, "main/dll/scarab.c"),
            Object(NonMatching, "main/dll/barrel.c"),
            Object(NonMatching, "main/dll/ladders.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/waterfallControl.c"),
            Object(NonMatching, "main/dll/backpack.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/landedArwing.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/staffAction.c"),
            Object(NonMatching, "main/dll/treasurechest.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cf_doorlight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/texscroll2.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/campfire.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/wallanimator.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/xyzanimator.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/genprops.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/gfxEmit.c"),
            Object(NonMatching, "main/dll/lightning.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/transporter.c"),
            Object(NonMatching, "main/dll/dll_00F3_flameblast.c"),
            Object(NonMatching, "main/dll/autoTransporter.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/fogcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/tFrameAnimator.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/screenOverlay.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/texScroll.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_147.c"),
            Object(NonMatching, "main/dll/cfguardian.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/alphaanim.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/groundAnimator.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/crackanim.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/babycloudrunner.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_14D.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cfprisonuncle.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/gcrobotlightbea.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cfperch.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/blasted.c"),
            Object(NonMatching, "main/dll/explodable.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_0106_scarab.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_0107_unused.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_0108_endobject.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_010D_portalspelldoor.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_010C_lanternfirefly.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_010B_fireflylantern.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/CFBaby.c"),
            Object(NonMatching, "main/dll/CF/CFPrisonGuard.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_011C_linkstaffle.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_011D_treasureche.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/CFtoggleswitch.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/CFforcecontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/treasureRelated0177.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/dll_17A.c"),
            Object(NonMatching, "main/dll/CF/CFlevelControl.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/CFTreasSharpy.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/CFchuckobj.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/CFwalltorch.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/moonseedbush.c"),
            Object(NonMatching, "main/dll/mmp_asteroid_re.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/holoPoint.c"),
            Object(NonMatching, "main/dll/mmp_moonrock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/MMP/mmp_barrel.c"),
            Object(NonMatching, "main/dll/MMP/mmp_levelcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/MMP/MMP_asteroid.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/MMP/MMP_moonrock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/MMP/MMP_gyservent.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/hightop.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0148_cfguardian.c"),
            Object(NonMatching, "main/dll/DR/dll_0149_cfwindlift.c"),
            Object(NonMatching, "main/dll/DR/dll_014A_cfpowerbase.c"),
            Object(NonMatching, "main/dll/DR/dll_014B_cfmaincryst.c"),
            Object(NonMatching, "main/dll/DR/dll_014C_cfcloudbaby.c"),
            Object(NonMatching, "main/dll/DR/dll_014E_cfprisongua.c"),
            Object(NonMatching, "main/dll/DR/dll_014F_cfprisonunc.c"),
            Object(NonMatching, "main/dll/DR/dll_0150_gcrobotligh.c"),
            Object(NonMatching, "main/dll/DR/dll_0153_cfperch.c"),
            Object(NonMatching, "main/dll/DR/dll_0154_cfprisoncag.c"),
            Object(NonMatching, "main/dll/DR/dll_0157_spiritdoors.c"),
            Object(NonMatching, "main/dll/DR/dll_0158_gunpowderbarrel.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0159_blasted.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/gasventControl.c"),
            Object(NonMatching, "main/dll/IM/IMicicle.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/IM/IMspacecraft.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIMlavaball.c"),
            Object(NonMatching, "main/dll/DIM/DIMlogfire.c"),
            Object(NonMatching, "main/dll/DIM/DIMsnowball.c"),
            Object(NonMatching, "main/dll/DIM/DIMboulder.c"),
            Object(NonMatching, "main/dll/DIM/DIMcannon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIMlavasmash.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIMExplosion.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIMwooddoor.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIMlevcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIM2conveyor.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIM2flameburst.c"),
            Object(NonMatching, "main/dll/DIM/DIM2snowball.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIM2projrock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIM2lift.c"),
            Object(NonMatching, "main/dll/DIM/DIM2icicle.c"),
            Object(NonMatching, "main/dll/DIM/DIMboss.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIMbossgut.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/dll_223.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DIM/DIMbossspit.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/vfp_lavapool.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mmsh_waterspike.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DF/rope.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DF/DFcradle.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DF/DFpulley.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DF/DFbarrel.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DF/DFbarrelanim.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DF/dll_0175_dfropenode.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DF/dll_0177_dfshdoor2s.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_017A_spiritprize.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_0179_dfshobjcre.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/creator19D.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/laser19F.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mmshrine/shrine.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mmshrine/shrine1C2.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/creator1C4.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dimbarrier.c"),
            Object(NonMatching, "main/dll/scene1C7.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/colrise.c"),
            Object(NonMatching, "main/dll/cup1C3.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/explosion.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/symbol.c"),
            Object(NonMatching, "main/dll/dimmagicbridge.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/shrine1CE.c"),
            Object(NonMatching, "main/dll/dim_tricky.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dimtruthhornice.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ped.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/worldobj.c"),
            Object(NonMatching, "main/dll/creator1D6.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/projball1D8.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/NW/NWsfx.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/NW/dll_1DB.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/NW/dll_1DC.c"),
            Object(NonMatching, "main/dll/NW/NWmammoth.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dim_boss.c"),
            Object(NonMatching, "main/dll/dim_bossgut.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SH/SHkillermushroom.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SH/SHrocketmushroom.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SH/SHspore.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SH/dll_1E7.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SH/lily.c"),
            Object(NonMatching, "main/dll/SH/dll_1E8.c"),
            Object(NonMatching, "main/dll/SH/SHthorntail.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SH/SHroot.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/SClevelcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/SCchieflightfoot.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/SClantern.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/SCcollectables.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/SCanimobj.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/SCtotemlogpuz.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/SCtotembondpuz.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/brokecannon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SP/SPshop.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SP/SPshopkeeper.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SP/SPdrape.c"),
            Object(NonMatching, "main/dll/IM/IMsnowbike.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRearthwalk.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CR/CRsnowbike.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRcloudrunner.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/dll_01BA_sctotempuzzle.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/SC/dll_01BB_sctotembond.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/platform1.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/VF/draghead.c"),
            Object(NonMatching, "main/dll/VF/lavaflow.c"),
            Object(NonMatching, "main/dll/DB/DBrockfall.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DB/DBpointmum.c"),
            Object(NonMatching, "main/dll/DB/DBwaterflow.c"),
            Object(NonMatching, "main/dll/DB/DBlightgo.c"),
            Object(NonMatching, "main/dll/DB/DBbullet.c"),
            Object(NonMatching, "main/dll/DB/DBprotection.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DB/DBdustgeezer.c"),
            Object(NonMatching, "main/dll/DB/DBstealerworm.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/TREX/TREX_levelcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/TREX/TREX_trex.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/TREX/TREX_Lazerwall.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRlaserturret.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRpushcart.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRCloudball.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRsimplehuman.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRcloudcage.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRshackle.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRhightop.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/DRpickup.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/BW/dll_0255_crsnowbike.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/BW/BWalphaanim.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/WCpushblock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/WClevcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/WCbeacon.c"),
            Object(NonMatching, "main/dll/WC/WCpressureSwitch.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/WCdial.c"),
            Object(NonMatching, "main/dll/WC/WClaser.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_801F0B50.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_01FE_cfpressures.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_01FF_dll1ff.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_01FD_wmlasertar.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_0200_dll200.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_0201_wmcolrise.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_0204_wmtorch.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/LGT/LGTpointlight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/LGT/LGTdirectionallight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WM/dll_0209_wmlevelcontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WM/dll_020A_wmgeneralscales.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/LGT/LGTcontrollight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/boulder.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/anim.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/chuka.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/baddie/chukachuck.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/tesla.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/infopoint.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/TrickyCurve.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/crate.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/crate2.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/zBomb.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/laser_unsupported.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/laserObj.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/fire.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/platform1.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dfplightni.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/CF/laser.c"),
            Object(NonMatching, "main/dfppowersl.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/worldasteroids.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/worldplanet_lighting.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/worldplanet.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/worldobj.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/snowclaw.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/crcloudrace.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/spellstone_idle.c"),
            Object(NonMatching, "main/spellstone.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/crfueltank.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/proximitymine_reset.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/proximitymine_update.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_024F_kt_rexlevel.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/obj_008A_kt_rex.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0251_kt_rexfloorswitch.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0252_kt_lazerwall.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0253_kt_lazerlight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0254_kt_fallingrocks.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0261_dr_lasercannon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0262_drakormissile.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0263_gm_mazewell.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0266_kytesmum.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0265_dr_creator.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0268_dr_cagecontrol.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0269_explodeplan.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_026B_dr_chimmey.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_026C_dr_cagewith.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_026E_dr_shackle.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0271_drakorhoverpad.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0272_hightop.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_026F_dr_generator.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/firepipe.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0279_dr_energydisc.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_027C_dr_lightbea.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_027E_drmusiccont.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0280_dr_cloudper.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0281_dr_earthcal.c"),
            Object(NonMatching, "main/dll/barrelgener.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/DR/dll_0283_dr_barrelgr.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/earthwalker.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_028B.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_028C_wcbouncycra.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0290_wcpushblock.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_028D_wclevelcont.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_028E_wcbeacon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0291_wctile.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_028F_wcpressures.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0292_wctrexstatu.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/suntemple.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0294_wctemple.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_0299.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0295_wcapertures.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0296_wctempledia.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0297_wctemplebri.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/WC/dll_0298_wcfloortile.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_029A_arwarwing.c"),
            Object(NonMatching, "main/dll/ARW/dll_029B_arwingandrossstuff.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_029C_arwarwingbo.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_029D_arwarwinggu.c"),
            Object(NonMatching, "main/dll/dll_029E_Dummy29E.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_029F_arwbombcoll.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ring.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "main/dll/ARW/dll_02A1_arwlevelcon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_02A2_arwspeedstr.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_02A3.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dll_02A4.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_02A5_arwgenerato.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_02A6_arwsquadron.c", cflags=cflags_dll_noopt),
            Object(MatchingFor("GSAE01"), "main/dll/ARW/dll_02A7_arwproximit.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/ARW/dll_02A8_arwblocker.c"),
            Object(NonMatching, "main/dll/LGT/dll_02A9_pointlight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/LGT/dll_02AA_directionallight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/LGT/dll_02AB_projectedlight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/LGT/dll_02AC_controllight.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/softbody.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/waterflowwe.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/tree.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/brokenpipe.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cmbsrc.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/dustmotesou.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/vortex.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cntcounter.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/timer.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/cnthitobjec.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mcupgrade.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mcupgradema.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mcstaffeffe.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/mclightning.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/gf_levelcon.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/andross.c"),
            Object(NonMatching, "main/dll/androsshand.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/androssbrain.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/dll/androssligh.c", cflags=cflags_dll_noopt),
            Object(NonMatching, "main/audio/synth_queue.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_seq_events.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_seq_dispatch.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_channel_scale.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_voice.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_volume.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_job_init.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/synth_jobs.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/data_tables.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/mcmd_wait.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/mcmd_loop.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/mcmd_setup.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/mcmd_exec.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/vid_get.c"),
            Object(NonMatching, "main/audio/voice_id.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/voice_unregister.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/adsr_setup.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/adsr_lowprec.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/vsample_events.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/snd_groups.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/sal_studio.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_dspctrl.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/snd3d_room.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/snd3d_calc.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/snd_core.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/inp_midi.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/inp_voice.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/inp_ctrl.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_break.c"),
            Object(MatchingFor("GSAE01"), "main/audio/hw_sample.c"),
            Object(NonMatching, "main/audio/hw_keyoff.c"),
            Object(NonMatching, "main/audio/hw_volume.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/hw_stream.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/aram_queue.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/aram_init.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/aram_data.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/sal_ai.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/sal_dsp.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "main/audio/snd_reverb.c", mw_version="GC/1.2.5n"),
            Object(NonMatching, "dolphin/axfx/reverb_std_create.c", mw_version="GC/1.2.5n"),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.c",
                mw_version="GC/1.2.5n",
                extra_cflags=["-inline", "off", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/k_sin.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/k_cos.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/e_sqrt.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "peephole", "-inline", "auto", "-use_lmw_stmw", "on", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                MatchingFor("GSAE01"),
                "dolphin/MSL_C/PPCEABI/bare/H/e_atan2.c",
                mw_version="GC/1.2.5n",
                extra_cflags=msl_math_extra,
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/s_tan.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions,peephole", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/k_tan.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/e_rem_pio2.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/s_floor.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
            Object(
                NonMatching,
                "dolphin/MSL_C/PPCEABI/bare/H/s_sin.c",
                mw_version="GC/1.2.5n",
                cflags=msl_math_o0_cflags,
                extra_cflags=["-O0", "-opt", "functions", "-inline", "auto", *msl_math_extra],
                progress_category="sdk",
            ),
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
