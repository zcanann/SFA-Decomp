# Loose DLL cleanup — REMAINING worklist

Snapshot of everything still to do for the loose `src/main/dll/*.c` cleanup pass 
(byte-exact / match-%-gated: dead-`FUN_` removal + unused include/extern pruning + readability, 
mirroring `src/main/dll/WM/dll_020C_wmspiritplace.c`). Driven by the workflow in 
`tools/dll_cleanup_wave.js` with helpers in `/tmp/dllclean/`.

## 1. Untackled main-queue files (queue indices 264–367): 104 files

Resume from index 264, 20 per chunk, 3-wide. Listed with current match %.

```
264  dll_018F_ecshshrine.c                    100.0%
265  dll_0191_ecshcreator.c                   100.0%
266  dll_0195_dbshshrine.c                    100.0%
267  dll_0196_dbshsymbol.c                    97.485%
268  dll_0197_dll197.c                        100.0%
269  dll_019A_dll19a.c                        100.0%
270  dll_01A7_ediblemushroom.c                98.991%
271  dll_01BD_paymentkiosk.c                  100.0%
272  dll_01CE_dll1ce.c                        99.85%
273  dll_01D6_dll1d6.c                        98.696%
274  dll_01DA_dll1da.c                        98.72%
275  dll_01DB_dll1db.c                        100.0%
276  dll_01DF_dll1df.c                        100.0%
277  dll_01F4_lamp.c                          100.0%
278  dll_01F6_flag.c                          100.0%
279  dll_01FC_laserbeam.c                     100.0%
280  dll_01FE_pressureswitch.c                98.537%
281  dll_0206_lightsource.c                   99.613%
282  dll_0219.c                               98.925%
283  dll_021B.c                               96.603%
284  dll_022C_dll22c.c                        98.851%
285  dll_0238_linkalevco.c                    100.0%
286  dll_023F_dbegg.c                         97.061%
287  dll_0240_gcrobotblast.c                  100.0%
288  dll_0241_drakorenergy.c                  100.0%
289  dll_0243_dbholecontrol1.c                99.924%
290  dll_024D_bossdrakor.c                    97.357%
291  dll_024E_drakordthornbush.c              99.789%
292  dll_025A_staticcamera.c                  100.0%
293  dll_025B_msplantings.c                   100.0%
294  dll_0266_kytesmum.c                      98.192%
295  dll_0269_explodeplan.c                   99.481%
296  dll_0273_firepipe.c                      100.0%
297  dll_0284_shopitem.c                      99.843%
298  dll_028B.c                               99.095%
299  dll_0299.c                               100.0%
300  dll_029B_arwingandrossstuff.c            97.982%
301  dll_029E_Dummy29E.c                      100.0%
302  dll_02A0_ring.c                          99.044%
303  dll_02A4.c                               99.784%
304  dll_02AE_waterflowwe.c                   98.81%
305  dll_02B0_brokenpipe.c                    100.0%
306  dll_02B1_cmbsrc.c                        96.363%
307  dll_02B2_dustmotesou.c                   100.0%
308  dll_02B6_cnthitobjec.c                   100.0%
309  dll_02B7_mcupgrade.c                     100.0%
310  dll_02B8_mcupgradema.c                   100.0%
311  dll_02B9_mcstaffeffe.c                   100.0%
312  dll_02BB_gflevelcon.c                    98.954%
313  dll_02BC_andross.c                       96.72%
314  dll_02BF_androssligh.c                   100.0%
315  dll_1e7.c                                95.471%
316  dll_3b.c                                 99.337%
317  dll_3e.c                                 94.464%
318  dll_43.c                                 100.0%
319  dll_4d.c                                 100.0%
320  dll_60.c                                 100.0%
321  dll_8011d918.c                           100.0%
322  dll_80136a40.c                           90.447%
323  dll_80161130.c                           100.0%
324  dll_801ac01c.c                           100.0%
325  dll_801b9ecc.c                           91.21%
326  dll_801d0828.c                           100.0%
327  dll_801d4198.c                           100.0%
328  dll_801e66dc.c                           100.0%
329  dll_8b.c                                 100.0%
330  dll_a6.c                                 100.0%
331  dll_b2.c                                 100.0%
332  dll_b3.c                                 100.0%
333  dll_b4.c                                 100.0%
334  dll_b6.c                                 97.2%
335  dll_b7.c                                 97.612%
336  dll_b8.c                                 100.0%
337  dll_bb.c                                 99.327%
338  dll_bc.c                                 100.0%
339  drcloudcage.c                            97.863%
340  drpickup.c                               100.0%
341  duster.c                                 99.058%
342  fall_ladders.c                           98.94%
343  fireflylantern.c                         99.26%
344  frontend_control.c                       100.0%
345  landedarwing.c                           100.0%
346  magicplant.c                             98.641%
347  maybetemplate.c                          93.288%
348  mmp_cratercritter.c                      91.531%
349  mmsh_waterspike.c                        100.0%
350  n_options.c                              94.866%
351  newseqobj.c                              95.886%
352  objfx.c                                  98.0%
353  picmenu.c                                99.246%
354  prof.c                                   98.917%
355  scchieflightfoot.c                       100.0%
356  seqobj11d.c                              94.112%
357  seqobj11e.c                              99.52%
358  skeetla.c                                96.061%
359  staffactivated_helpers.c                 100.0%
360  swarmbaddie.c                            93.321%
361  texscroll2.c                             100.0%
362  trex_lazerwall.c                         97.183%
363  tricky.c                                 95.312%
364  tumbleweedbush.c                         97.916%
365  viewfinder.c                             100.0%
366  warppad.c                                100.0%
367  weapone6.c                               98.765%
```

## 2. Redo backlog (API-500/529-affected; cleaned partially or review-skipped): 9 files

Re-run through the full pipeline (clean → Sonnet review → fix).
```
dll_001E_effect5.c
dll_001F_effect6.c
dll_0020_effect7.c
dll_0022_effect9.c
dll_0023_effect10.c
dll_0027_effect14.c
dll_009D_dll9dfunc0.c
dll_00A0_dlla0func0.c
dll_00A3_dlla3func0.c
```

## 3. Header cleanup backlog: 3

Agents touched these headers out-of-scope; the `.c` edit was reverted but the header may still 
carry dead `FUN_`/decls. Sweep separately (header-aware).
```
header for later sweep:
include/main/dll/dll_0035_saveselectscreen.h
include/main/dll/dll_0104_smallbasket.h
```

## 4. Recheck (concurrent-edit collisions; other agent's version kept): 3

```
dll_0000_baby_snowworm.c
src/main/dll/dll_00C6_animatedobj.c
src/main/dll/dll_00CF_cannonclaw.c
```

## 5. Second-pass: old-pipeline files

65 files cleaned before dead-`FUN_` removal existed — see `docs/dll_loose_second_pass.md` 
(14 still contain `FUN_`). Re-run through the current pipeline.

## Resume procedure
```
# per chunk, bump START by 20 (264, 284, 304, ...):
python3 /tmp/dllclean/prep_chunk.py <START> 20   # pull, rebuild, refresh baselines, set window
#   launch Workflow on tools/dll_cleanup_wave.js
python3 /tmp/dllclean/finish_chunk.py <START> 20 # verify (match-gated), commit-per-file, push
```
NOTE: `/tmp/dllclean/` is ephemeral. `queue.json` is rebuildable from the 'needs-work' heuristic 
(no leading `/*` header OR contains `FUN_80`/`extraout_`/`in_rN`), excluding files already cleaned this session.
