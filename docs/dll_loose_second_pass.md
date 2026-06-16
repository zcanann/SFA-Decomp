# Loose DLL cleanup — second-pass worklist

Files cleaned this session under the **old md5-exact pipeline** (before dead-`FUN_` removal + aggressive unused-symbol pruning were added). They are byte-exact and committed, but may still carry dead `FUN_` bodies, unused `FUN_` declarations, and unused includes/externs. Re-run them through the upgraded `tools/dll_cleanup_wave.js` pipeline (match-%-gated) for a second pass.

Total: **65** files.

| file | FUN_ total | FUN_ defs | FUN_ decls | #includes | externs |
|---|---:|---:|---:|---:|---:|
| dll_0109_unk.c | 53 | 2 | 52 | 9 | 27 |
| dll_0139_hitanimator.c | 22 | 2 | 14 | 7 | 19 |
| dll_016B_magiclight.c | 22 | 4 | 10 | 7 | 23 |
| dll_0053_cameramodecloudrunner.c | 21 | 3 | 16 | 5 | 32 |
| dll_0136_waveanimator.c | 21 | 2 | 14 | 6 | 33 |
| dll_0137_alphaanimator.c | 20 | 2 | 14 | 6 | 23 |
| dll_01FF_dll1ff.c | 20 | 3 | 12 | 4 | 26 |
| dll_00F3_flameblast.c | 18 | 1 | 8 | 3 | 26 |
| dll_0173_linklevcontrol.c | 14 | 1 | 8 | 4 | 17 |
| dll_0038_weirdunusedmenu.c | 13 | 1 | 6 | 2 | 25 |
| dll_003A_dummy3a.c | 12 | 1 | 6 | 1 | 5 |
| dll_01CF_dll1cf.c | 10 | 1 | 1 | 14 | 5 |
| dll_013B_wallanimator.c | 1 | 1 | 0 | 7 | 22 |
| dll_01F5_shipbattle.c | 1 | 1 | 0 | 6 | 17 |
| attractmovie.c | 0 | 0 | 0 | 1 | 1 |
| backpack.c | 0 | 0 | 0 | 6 | 19 |
| camlockon.c | 0 | 0 | 0 | 2 | 1 |
| dfbarrel.c | 0 | 0 | 0 | 3 | 3 |
| dll_0024_effect11.c | 0 | 0 | 0 | 4 | 28 |
| dll_0025_effect12.c | 0 | 0 | 0 | 4 | 22 |
| dll_0046_cameramodedebug.c | 0 | 0 | 0 | 6 | 17 |
| dll_0048_cameramodestatic.c | 0 | 0 | 0 | 6 | 5 |
| dll_0080_dll80func0.c | 0 | 0 | 0 | 3 | 10 |
| dll_0082_dll82func0.c | 0 | 0 | 0 | 3 | 11 |
| dll_0083_dll83func0.c | 0 | 0 | 0 | 3 | 19 |
| dll_0088_dll88func0.c | 0 | 0 | 0 | 3 | 8 |
| dll_008A_dll8afunc0.c | 0 | 0 | 0 | 3 | 5 |
| dll_0090_dll90func0.c | 0 | 0 | 0 | 3 | 17 |
| dll_0094_dll94func0.c | 0 | 0 | 0 | 2 | 14 |
| dll_0095_dll95func0.c | 0 | 0 | 0 | 2 | 12 |
| dll_0099_dll99func0.c | 0 | 0 | 0 | 2 | 14 |
| dll_00A8_dlla8func0.c | 0 | 0 | 0 | 2 | 15 |
| dll_00D4_skeetlawall.c | 0 | 0 | 0 | 2 | 3 |
| dll_00FC_babycloudrunner.c | 0 | 0 | 0 | 5 | 7 |
| dll_0127_dll127.c | 0 | 0 | 0 | 3 | 5 |
| dll_012F_barrelpad.c | 0 | 0 | 0 | 1 | 12 |
| dll_0134_texscroll2.c | 0 | 0 | 0 | 3 | 9 |
| dll_013D_explodeanimator.c | 0 | 0 | 0 | 2 | 6 |
| dll_0142_felevcontrol.c | 0 | 0 | 0 | 4 | 2 |
| dll_017D_rollingbarrel.c | 0 | 0 | 0 | 7 | 39 |
| dll_018E_mmshwaterspike.c | 0 | 0 | 0 | 3 | 10 |
| dll_01E4_magicmaker.c | 0 | 0 | 0 | 2 | 11 |
| dll_0263_gmmazewell.c | 0 | 0 | 0 | 2 | 0 |
| dll_0293_suntemple.c | 0 | 0 | 0 | 2 | 0 |
| dll_0294_wctemple.c | 0 | 0 | 0 | 2 | 0 |
| dll_02A3.c | 0 | 0 | 0 | 2 | 0 |
| dll_02AF_tree.c | 0 | 0 | 0 | 2 | 0 |
| dll_02B3_vortex.c | 0 | 0 | 0 | 2 | 0 |
| dll_02B4_cntcounter.c | 0 | 0 | 0 | 3 | 0 |
| dll_02B5_timer.c | 0 | 0 | 0 | 3 | 0 |
| dll_02BA_mclightning.c | 0 | 0 | 0 | 3 | 4 |
| dll_02BD_androsshand.c | 0 | 0 | 0 | 2 | 0 |
| dll_02BE_androssbrain.c | 0 | 0 | 0 | 2 | 0 |
| dll_223.c | 0 | 0 | 0 | 6 | 19 |
| dll_4e.c | 0 | 0 | 0 | 7 | 18 |
| dll_8010a104.c | 0 | 0 | 0 | 3 | 3 |
| dll_801814d0.c | 0 | 0 | 0 | 9 | 19 |
| drlaserturret.c | 0 | 0 | 0 | 7 | 33 |
| expgfxresource.c | 0 | 0 | 0 | 3 | 0 |
| infopoint.c | 0 | 0 | 0 | 1 | 4 |
| mmp_critterspit.c | 0 | 0 | 0 | 1 | 6 |
| mmp_gyservent.c | 0 | 0 | 0 | 1 | 12 |
| pathcam.c | 0 | 0 | 0 | 5 | 3 |
| sclantern.c | 0 | 0 | 0 | 3 | 8 |
| tesla.c | 0 | 0 | 0 | 4 | 4 |

## Quick-queue (files still containing any FUN_)

```
dll_0038_weirdunusedmenu.c
dll_003A_dummy3a.c
dll_0053_cameramodecloudrunner.c
dll_00F3_flameblast.c
dll_0109_unk.c
dll_0136_waveanimator.c
dll_0137_alphaanimator.c
dll_0139_hitanimator.c
dll_013B_wallanimator.c
dll_016B_magiclight.c
dll_0173_linklevcontrol.c
dll_01CF_dll1cf.c
dll_01F5_shipbattle.c
dll_01FF_dll1ff.c
```
