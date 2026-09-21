# The never-compiled sources, adjudicated

Population law (C110): the build's population is `build.ninja`, not the filesystem.
At the pristine tree the partition is **1005 compiled / 1070 on disk / 65 never
compiled on their own** — the earlier "66 / 1071" was measured in a worktree
carrying one stray untracked probe `.c`; at every recent revision the tracked
tree gives 65.  `tools/source_coverage_audit.py` prints the partition and
carries the controls.

Three of the 65 are **live by #include**: `musyx/runtime/snd3dgroup.c` is a
three-line shim that `#include`s them, so their text reaches the DOL and they
are population for every source-text screen (`live_sources()`).  The other
**62 are dead**: no path to the DOL, and text found only in them is not
evidence about the binary (that mistake was made once, with
`__ppc_eabi_init.cpp`'s three-`bl` `__init_hardware`).

Verdict key:

* **LIVE-INC** — live by inclusion; population, never delete.
* **DUP-DIV** — dead duplicate of a compiled unit whose content DIVERGES from
  the compiled truth; the dangerous class for a reader, screens now exclude it.
* **VENDOR-SUP** — vendor source superseded by a compiled variant of the same
  role (the compiled sibling is the truth about what shipped).
* **VENDOR** — vendor SDK/runtime source with no DOL presence at all: none of
  its function or object names resolve to any address in `symbols.txt`, and no
  split unit corresponds to it.  Retail's link never included it.

Every symbol-name overlap between an orphan and the DOL was resolved to its
owning split unit; **all owners are compiled units** — no orphan feeds a carve,
so the "should-be-compiled" class is EMPTY.

| # | file | verdict | evidence |
|---|------|---------|----------|
| 1 | `musyx/runtime/snd3d.c` | LIVE-INC | `#include`d by compiled `snd3dgroup.c`; `s3dInit`/`s3dHandle`/... resolve into `snd3dgroup` `.text` |
| 2 | `musyx/runtime/snd3d_calc.c` | LIVE-INC | same shim; `CalcEmitter`, `AddRunningEmitter`, ... |
| 3 | `musyx/runtime/snd3d_room.c` | LIVE-INC | same shim; `CheckRoomStatus`, `UpdateRoomDistances`, ... |
| 4 | `dolphin/os/__start.c` | DUP-DIV | duplicate of compiled `Runtime.PPCEABI.H/__start.c` (alternate import: `SECTION_INIT` externs, `Debug_BBA_8032EFE0`); its `__start`/`__init_registers`/`__init_data`/`__check_pad3` all resolve to the compiled unit's `.init` |
| 5 | `dolphin/os/__ppc_eabi_init.cpp` | DUP-DIV | the C109 misleader: its `__init_hardware` has three `bl`s, retail's (in compiled `__start.c`, 0x20 @ .init:0x80003354) has two; sibling `.c` IS compiled |
| 6 | `dolphin/axfx/reverb_std.c` | VENDOR-SUP | full vendor AXFX source, partially adapted (spells `axfx_reverb_std_f32_*` pool names); retail linked only 7 of its 14 functions, as the compiled two-TU split `reverb_std_create.c`+`reverb_std_callback.c` |
| 7 | `dolphin/os/OSTimer.c` | VENDOR-SUP | its `DecrementerException{Callback,Handler}` live in compiled `OSAlarm.c`; no `OS*Timer` API in symbols.txt |
| 8 | `dolphin/os/OSInterruptUnused.c` | VENDOR-SUP | its `SetInterruptMask` lives in compiled `OSInterrupt.c`; `OSGet/OSSetInterruptMask` absent from the DOL |
| 9 | `MSL_C/PPCEABI/bare/H/math_ppc.c` | VENDOR-SUP | MSL `acosf`/`powf`; retail's come from compiled `main/acosf.c` and `exponentialsf.c` |
| 10 | `Runtime.PPCEABI.H/Gecko_ExceptionPPC.cp` | VENDOR-SUP | MW C++ exception runtime; only `__register_fragment`/`__unregister_fragment` shipped, from compiled `fragment.c`; the DOL has no C++ EH machinery |
| 11 | `dolphin/TRK_MINNOW_DOLPHIN/main.c` | VENDOR-SUP | DDH transport driver (`ddh_cc_*`, none in DOL); compiled `main_TRK.c` is the linked main |
| 12 | `dolphin/TRK_MINNOW_DOLPHIN/main_gdev.c` | VENDOR-SUP | GDEV transport twin of #11 (`gdev_cc_*`, none in DOL) |
| 13–65 | the remaining 53 | VENDOR | zero symbol-name overlap with `symbols.txt`; no double-precision fdlibm (`__ieee754_*`, `atan`, `cos`, `sqrt`...), no `__AXCompressorTable`, no AX/axart/axfx/mix/mcc/hio/GX-verify/quat/OSFatal/OSSemaphore/OSUtf/VI-philips API in the DOL |

Row 13–65 members: `Runtime.PPCEABI.H/{CPlusLibPPC.cp, NMWException.cp, New.cp, ptmf.c}`;
`MSL_C/bare/H/{e_acos,e_fmod,extras,float,k_rem_pio2,s_atan,s_cos,signal,w_acos,w_atan2,w_fmod,w_pow,w_sqrt}.c`;
`TRK_MINNOW_DOLPHIN/{CircleBuffer,UDP_Stubs}.c`;
`ax/{AXAlloc,AXAux,AXCL,AXComp,AXOut,AXProf,AXSPB,AXVPB}.c`; `axart/{axart,axart3d}.c`;
`axfx/{axfx,chorus,delay,reverb_hi,reverb_hi_4ch}.c`; `dvd/dvdidutils.c`;
`gx/{GXSave,GXVerifRAS,GXVerifXF,GXVerify,GXVert}.c`; `hio/hio.c`; `mcc/{fio,mcc}.c`;
`mix/mix.c`; `mtx/{mtx44vec,quat}.c`; `os/{OSFatal,OSSemaphore,OSUtf,time.dolphin}.c`;
`vi/{gpioexi,i2c,initphilips}.c`.

**Nothing is deleted.** The vendor files document what the SDKs shipped; the
two DUP-DIV files are load-bearing specimens in `source_coverage_audit.py`'s
self-test; and the screens now select their population from `live_sources()`,
so dead text no longer spends screen rows or masquerades as evidence.
