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
            Object(NonMatching, "Runtime.PPCEABI.H/__start.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__mem.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/mem_TRK.s"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/__exception.s"),
            Object(NonMatching, "Runtime.PPCEABI.H/__va_arg.c"),
            Object(Matching, "Runtime.PPCEABI.H/global_destructor_chain.c"),
            Object(NonMatching, "Runtime.PPCEABI.H/runtime.s"),
            Object(Matching, "Runtime.PPCEABI.H/__init_cpp_exceptions.cpp"),
            Object(MatchingFor("GSAE01"), "Runtime.PPCEABI.H/fragment.s"),
        ],
    },
    DolphinLib(
        "os",
        [
            Object(NonMatching, "dolphin/os/OS.c"),
            Object(NonMatching, "dolphin/os/OSAlarm.c"),
            Object(NonMatching, "dolphin/os/OSAlloc.c"),
            Object(NonMatching, "dolphin/os/OSArena.c"),
            Object(NonMatching, "dolphin/os/OSAudioSystem.c"),
            Object(NonMatching, "dolphin/os/OSCache.c"),
            Object(NonMatching, "dolphin/os/OSContext.c"),
            Object(NonMatching, "dolphin/os/OSError.c"),
            Object(NonMatching, "dolphin/os/OSFont.c"),
            Object(NonMatching, "dolphin/os/OSInterrupt.c"),
            Object(NonMatching, "dolphin/os/OSMemory.c"),
            Object(NonMatching, "dolphin/os/OSReboot.c"),
            Object(NonMatching, "dolphin/os/OSReset.c"),
            Object(NonMatching, "dolphin/os/OSResetSW.c"),
            Object(NonMatching, "dolphin/os/OSRtc.c"),
            Object(NonMatching, "dolphin/os/OSSync.c"),
            Object(NonMatching, "dolphin/os/OSThread.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/OSTime.c"),
            Object(MatchingFor("GSAE01"), "dolphin/os/__ppc_eabi_init.c"),
        ],
    ),
    DolphinLib(
        "base",
        [
            Object(NonMatching, "dolphin/base/PPCArch.c"),
        ],
    ),
    DolphinLib(
        "db",
        [
            Object(NonMatching, "dolphin/db/db.c"),
        ],
    ),
    DolphinLib(
        "mtx",
        [
            Object(NonMatching, "dolphin/mtx/mtx.c", source="dolphin/mtx/mtx.c"),
            Object(NonMatching, "dolphin/mtx/mtxvec.c", source="dolphin/mtx/mtxvec.c"),
            Object(NonMatching, "dolphin/mtx/vec.c", source="sdk/mtx/vec.c"),
            Object(NonMatching, "dolphin/mtx/mtx44.c"),
            Object(NonMatching, "dolphin/mtx/mtx44vec.c"),
        ],
    ),
    DolphinLib(
        "dvd",
        [
            Object(NonMatching, "dolphin/dvd/dvdlow.c"),
            Object(NonMatching, "dolphin/dvd/dvdfs.c"),
            Object(NonMatching, "dolphin/dvd/dvd.c"),
            Object(NonMatching, "dolphin/dvd/dvdqueue.c"),
            Object(NonMatching, "dolphin/dvd/dvderror.c"),
            Object(NonMatching, "dolphin/dvd/fstload.c"),
            Object(NonMatching, "dolphin/dvd/dvdFatal.c"),
            Object(NonMatching, "dolphin/dvd/dvdidutils.c"),
        ],
    ),
    DolphinLib(
        "ai",
        [
            Object(NonMatching, "dolphin/ai/ai.c"),
        ],
    ),
    DolphinLib(
        "ar",
        [
            Object(NonMatching, "dolphin/ar/ar.c"),
            Object(NonMatching, "dolphin/ar/arq.c"),
        ],
    ),
    DolphinLib(
        "dsp",
        [
            Object(NonMatching, "dolphin/dsp/dsp.c"),
            Object(NonMatching, "dolphin/dsp/dsp_task.c"),
            Object(NonMatching, "dolphin/dsp/dsp_debug.c"),
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
            Object(NonMatching, "dolphin/si/SIBios.c"),
            Object(NonMatching, "dolphin/si/SISamplingRate.c"),
        ],
    ),
    DolphinLib(
        "pad",
        [
            Object(NonMatching, "dolphin/pad/Pad.c"),
            Object(NonMatching, "dolphin/pad/Padclamp.c"),
        ],
    ),
    DolphinLib(
        "exi",
        [
            Object(NonMatching, "dolphin/exi/EXIBios.c"),
            Object(NonMatching, "dolphin/exi/EXIUart.c"),
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
            Object(NonMatching, "dolphin/gx/GXInit.c"),
            Object(NonMatching, "dolphin/gx/GXFifo.c"),
            Object(NonMatching, "dolphin/gx/GXMisc.c"),
            Object(NonMatching, "dolphin/gx/GXLight.c"),
            Object(NonMatching, "dolphin/gx/GXTexture.c"),
            Object(NonMatching, "dolphin/gx/GXBump.c"),
            Object(NonMatching, "dolphin/gx/GXAttr.c"),
            Object(NonMatching, "dolphin/gx/GXDisplayList.c"),
            Object(NonMatching, "dolphin/gx/GXFrameBuf.c"),
            Object(NonMatching, "dolphin/gx/GXGeometry.c"),
            Object(NonMatching, "dolphin/gx/GXPerf.c"),
            Object(NonMatching, "dolphin/gx/GXPixel.c"),
            Object(NonMatching, "dolphin/gx/GXSave.c"),
            Object(NonMatching, "dolphin/gx/GXStubs.c"),
            Object(NonMatching, "dolphin/gx/GXTev.c"),
            Object(NonMatching, "dolphin/gx/GXTransform.c"),
            Object(NonMatching, "dolphin/gx/GXVerifRAS.c"),
            Object(NonMatching, "dolphin/gx/GXVerifXF.c"),
            Object(NonMatching, "dolphin/gx/GXVerify.c"),
            Object(NonMatching, "dolphin/gx/GXVert.c"),
        ],
    ),
    DolphinLib(
        "card",
        [
            Object(NonMatching, "dolphin/card/CARDBios.c"),
            Object(NonMatching, "dolphin/card/CARDUnlock.c"),
            Object(NonMatching, "dolphin/card/CARDRdwr.c"),
            Object(NonMatching, "dolphin/card/CARDBlock.c"),
            Object(NonMatching, "dolphin/card/CARDDir.c"),
            Object(NonMatching, "dolphin/card/CARDCheck.c"),
            Object(NonMatching, "dolphin/card/CARDMount.c"),
            Object(NonMatching, "dolphin/card/CARDFormat.c"),
            Object(NonMatching, "dolphin/card/CARDOpen.c"),
            Object(NonMatching, "dolphin/card/CARDCreate.c"),
            Object(NonMatching, "dolphin/card/CARDRead.c"),
            Object(NonMatching, "dolphin/card/CARDWrite.c"),
            Object(NonMatching, "dolphin/card/CARDDelete.c"),
            Object(NonMatching, "dolphin/card/CARDStat.c"),
            Object(NonMatching, "dolphin/card/CARDNet.c"),
        ],
    ),
    DolphinLib(
        "axfx",
        [
            Object(NonMatching, "dolphin/axfx/axfx.c"),
            Object(NonMatching, "dolphin/axfx/chorus.c"),
            Object(NonMatching, "dolphin/axfx/delay.c"),
            Object(NonMatching, "dolphin/axfx/reverb_hi.c"),
            Object(NonMatching, "dolphin/axfx/reverb_hi_4ch.c"),
            Object(NonMatching, "dolphin/axfx/reverb_std.c"),
        ],
    ),
    DolphinLib(
        "vi",
        [
            Object(NonMatching, "dolphin/vi/vi.c"),
            Object(NonMatching, "dolphin/vi/gpioexi.c"),
            Object(NonMatching, "dolphin/vi/i2c.c"),
            Object(NonMatching, "dolphin/vi/initphilips.c"),
        ],
    ),
    DolphinLib(
        "thp",
        [
            Object(NonMatching, "dolphin/thp/THPDec.c"),
            Object(MatchingFor("GSAE01"), "dolphin/thp/THPAudio.c"),
        ],
    ),
    DolphinLib(
        "OdemuExi2",
        [
            Object(NonMatching, "dolphin/OdemuExi2/DebuggerDriver.c"),
        ],
    ),
    DolphinLib(
        "odenotstub",
        [
            Object(NonMatching, "dolphin/odenotstub/odenotstub.c"),
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
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/mainloop.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/nubevent.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/nubinit.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/msg.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/msgbuf.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/serpoll.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/usr_put.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/dispatch.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/msghndlr.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/support.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/mutex_TRK.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/notify.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/flush_cache.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/mem_TRK.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/targimpl.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/targsupp.s"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/mpc_7xx_603e.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/main_TRK.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/dolphin_trk_glue.c"),
            Object(MatchingFor("GSAE01"), "dolphin/TRK_MINNOW_DOLPHIN/targcont.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/target_options.c"),
            Object(NonMatching, "dolphin/TRK_MINNOW_DOLPHIN/mslsupp.c"),
        ],
    },
    DolphinLib(
        "MSL_C",
        [
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/abort_exit.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/alloc.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/ansi_files.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/ansi_fp.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/buffer_io.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/direct_io.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/file_io.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/FILE_POS.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/mbstring.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/mem.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/mem_funcs.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/misc_io.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/printf.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/string.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/wchar_io.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_copysign.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_frexp.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_ldexp.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_modf.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/gamecube.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/uart_console_io_gcn.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/rand.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/math_ppc.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/k_cos.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/k_sin.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/e_sqrt.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_tan.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/extras.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_floor.c"),
            Object(NonMatching, "dolphin/MSL_C/PPCEABI/bare/H/s_sin.c"),
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
