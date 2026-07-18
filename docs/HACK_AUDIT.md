# Hack Purge Audit

Owner-directed hyper-aggressive purge of all match hacks (pragmas, gotos,
__declspec section forcing, match-volatiles, pool reconstructions), accepting
match/linkage regressions in exchange for plausible original-shaped source.

## Recovery

The complete pre-purge state is pinned at git tag `pre-hack-purge`
(commit 556a5ac0db). To consult or restore any prior shape:

- Whole tree: `git diff pre-hack-purge` / `git checkout pre-hack-purge -- <file>`
- Per-file hack detail: `git diff pre-hack-purge -- src/main/<file>.c`
- Load-bearing hack inventory with probed per-hack costs: session logs referenced
  in the wave-1/2 cleanup commits (6baee808c1, f4fc2e4464, bb1f92748d).

## Policy going forward

These constructs are BANNED from game code (`src/main/`, `src/track/`) — see the
"Banned constructs" section of CLAUDE.md, which is the enforced source of truth:
no `#pragma` of any kind, no `goto`, no `__declspec(section ...)`, no
match-volatiles/CSE-blocking puns, no `lbl_`-named pool-reconstruction consts.
Units that cannot match without them stay NonMatching or await a TU re-split.

## Waves 1-2 (complete purge of src/main + src/track)

Overall fuzzy 99.841156 -> 90.559875.
Roughly 3,200 hack lines removed in total (all pragmas, all gotos, all __declspec
section forcing, match-volatiles, pool reconstructions). Everything compiles; DOL
byte-identical via demotions (retail objs link in place of changed units). Hardware
volatiles (GX FIFO, VI/PE interrupt state) retained. Per-lane hack detail lives in the
purge commits and the incremental per-file audit fragments referenced there.

### Per-unit fuzzy impact (vs pre-hack-purge tag)

| Unit | Before | After | Delta |
|---|---|---|---|
| main/main/dll/dll_0063_dll63func0 | 100.0000 | 2.3491 | -97.6509 |
| main/main/dll/dll_0099_dll99func0 | 100.0000 | 7.6017 | -92.3983 |
| main/main/dll/dll_0097_dll97func0 | 100.0000 | 7.6017 | -92.3983 |
| main/main/dll/dll_0094_dll94func0 | 100.0000 | 7.6017 | -92.3983 |
| main/main/dll/dll_0092_dll92func0 | 100.0000 | 7.6017 | -92.3983 |
| main/main/audio/synth_seq_events | 100.0000 | 20.7301 | -79.2699 |
| main/main/dll/dll_001D_effect4 | 100.0000 | 37.6655 | -62.3345 |
| main/main/dll/dll_0159_blasted | 100.0000 | 37.7962 | -62.2038 |
| main/main/dll/dll_0020_effect7 | 100.0000 | 38.1626 | -61.8374 |
| main/main/dll/dll_001B_effect2 | 100.0000 | 38.7782 | -61.2218 |
| main/main/dll/dll_0021_effect8 | 100.0000 | 39.2042 | -60.7958 |
| main/main/dll/dll_001A_effect1 | 100.0000 | 39.4618 | -60.5382 |
| main/main/dll/dll_001E_effect5 | 100.0000 | 40.1930 | -59.8070 |
| main/main/dll/dll_001F_effect6 | 100.0000 | 42.3198 | -57.6802 |
| main/main/dll/dll_0022_effect9 | 100.0000 | 44.3311 | -55.6689 |
| main/main/worldobj | 99.9645 | 45.0549 | -54.9096 |
| main/main/dll/dll_00CB_dllcb | 100.0000 | 45.7133 | -54.2867 |
| main/main/dll/DIM/dll_01CA_dimexplosion | 100.0000 | 46.7400 | -53.2600 |
| main/main/dll/dll_0139_hitanimator | 100.0000 | 46.8056 | -53.1944 |
| main/main/dll/MMP/dll_0181_mmptrenchfx | 100.0000 | 50.1566 | -49.8434 |
| main/main/dll/dll_00CF_cannonclaw | 100.0000 | 50.5923 | -49.4077 |
| main/main/dll/DIM/dll_01CC_dimmagicbridge | 100.0000 | 50.7026 | -49.2974 |
| main/main/dll/dll_014C_babycloudrunner | 99.6883 | 51.4056 | -48.2828 |
| main/main/textrender | 99.4267 | 51.5785 | -47.8483 |
| main/main/dll/dll_0018_boneparticleeffect | 99.8472 | 52.4367 | -47.4105 |
| main/main/dll/dll_0016_screentransition | 99.5761 | 53.7629 | -45.8132 |
| main/main/dll/MMP/dll_0180_mmpasteroidre | 100.0000 | 55.8748 | -44.1252 |
| main/main/dll/dll_02BD_androsshand | 100.0000 | 56.1128 | -43.8872 |
| main/main/dll/dll_000D_playershadow | 100.0000 | 56.4132 | -43.5868 |
| main/main/track_dolphin | 99.0354 | 57.2364 | -41.7990 |
| main/main/dll/dll_0031_minimap | 99.3734 | 58.3480 | -41.0255 |
| main/main/vecmath | 99.9213 | 59.1037 | -40.8176 |
| main/main/dll/dll_02C0_front | 99.7227 | 58.9538 | -40.7689 |
| main/main/dll/dll_016C_dll16c | 100.0000 | 59.5588 | -40.4412 |
| main/main/lightmap | 99.7713 | 60.9359 | -38.8354 |
| main/main/dll/dll_00CC_chukchuk | 100.0000 | 62.2481 | -37.7519 |
| main/main/objanim | 99.4767 | 61.8438 | -37.6330 |
| main/main/dll/dll_016A_crrockfall | 100.0000 | 62.5634 | -37.4366 |
| main/main/dll/dll_00D7_kaldachompspit | 100.0000 | 63.0135 | -36.9865 |
| main/main/dll/grimblegroup | 100.0000 | 63.0332 | -36.9668 |
| main/main/dll/dll_0184_animsharpclaw | 100.0000 | 63.2147 | -36.7853 |
| main/main/model | 99.7706 | 63.0566 | -36.7140 |
| main/main/dll/expgfx | 99.2022 | 62.7545 | -36.4476 |
| main/main/dll/NW/dll_01A5_nwlevcontrol | 100.0000 | 64.4007 | -35.5993 |
| main/main/dll/dll_02BB_gflevelcon | 100.0000 | 65.1733 | -34.8267 |
| main/main/curves | 100.0000 | 66.1867 | -33.8133 |
| main/main/dll/WC/dll_0296_wctempledia | 100.0000 | 67.7368 | -32.2632 |
| main/main/dll/CC/dll_0189_ccsharpclawpad | 100.0000 | 67.8719 | -32.1281 |
| main/main/dll/dll_3b | 100.0000 | 68.0723 | -31.9277 |
| main/main/main | 99.8279 | 68.0867 | -31.7412 |
| main/main/dll/dll_0035_saveselectscreen | 99.9292 | 68.3547 | -31.5745 |
| main/main/rcp_dolphin | 99.7276 | 68.2845 | -31.4431 |
| main/main/audio/sal_volume | 100.0000 | 69.6708 | -30.3292 |
| main/main/dll/dll_0255_snowbike | 100.0000 | 69.6763 | -30.3237 |
| main/main/pi_dolphin | 98.6446 | 68.4667 | -30.1779 |
| main/main/dll/dll_011A_decoration11a | 100.0000 | 70.3114 | -29.6886 |
| main/main/dll/dll_0040_credits | 100.0000 | 70.4585 | -29.5415 |
| main/main/dll/DR/dll_0281_drearthcal | 100.0000 | 70.8681 | -29.1319 |
| main/main/dll/dll_0041_warpstoneui | 99.6296 | 70.8788 | -28.7508 |
| main/main/dll/dll_025B_msplantings | 100.0000 | 71.4044 | -28.5956 |
| main/main/object | 99.9370 | 71.5331 | -28.4040 |
| main/main/dll/dll_0038_weirdunusedmenu | 100.0000 | 72.3010 | -27.6990 |
| main/main/objlib | 99.9354 | 72.3720 | -27.5633 |
| main/main/dll/DIM/dim2lift | 100.0000 | 72.4988 | -27.5012 |
| main/main/dll/DIM/dll_01C7_dimlavasmash | 99.6981 | 72.5283 | -27.1698 |
| main/main/dll/dll_801b9ecc | 100.0000 | 73.2617 | -26.7383 |
| main/main/dll/dll_0150_gcrobotlightbea | 100.0000 | 73.3571 | -26.6429 |
| main/main/dll/dll_016B_magiclight | 100.0000 | 73.6266 | -26.3734 |
| main/main/audio/snd_core | 100.0000 | 73.8426 | -26.1574 |
| main/main/dll/dll_00CD_iceball | 100.0000 | 73.9626 | -26.0374 |
| main/main/dll/ARW/dll_02A8_arwblocker | 100.0000 | 74.4741 | -25.5259 |
| main/main/dll/dll_02AF_tree | 100.0000 | 74.6157 | -25.3843 |
| main/main/dll/dll_010B_fireflylantern | 100.0000 | 75.1748 | -24.8252 |
| main/main/dll/dll_0109_unk | 100.0000 | 75.2237 | -24.7763 |
| main/main/audio/snd_groups | 100.0000 | 75.4011 | -24.5989 |
| main/main/gametext | 99.7635 | 75.1847 | -24.5787 |
| main/main/dll/dll_00F1_invhit | 99.9045 | 75.3938 | -24.5107 |
| main/main/dll/SC/dll_01B7_scmusictree | 100.0000 | 75.6706 | -24.3294 |
| main/main/dll/dll_004D_cameramodenpcspeak | 100.0000 | 76.0471 | -23.9529 |
| main/main/audio/hw_samplemem | 100.0000 | 76.4762 | -23.5238 |
| main/main/dll/dll_0037_optionsscreen | 100.0000 | 76.8072 | -23.1928 |
| main/main/dll/dll_000C_projgfx | 100.0000 | 77.2727 | -22.7273 |
| main/main/dll/dll_003B_menu | 100.0000 | 77.3333 | -22.6667 |
| main/main/dll/IM/dll_0169_imicemountain | 100.0000 | 78.1153 | -21.8847 |
| main/main/gameloop | 99.7745 | 78.0871 | -21.6874 |
| main/main/dll/dll_00EC_infopoint | 100.0000 | 78.3171 | -21.6829 |
| main/main/dll/dll_0137_alphaanimator | 100.0000 | 78.5640 | -21.4360 |
| main/main/dll/dll_003F_dll3f | 100.0000 | 78.8919 | -21.1081 |
| main/main/light | 100.0000 | 79.4737 | -20.5263 |
| main/main/dll/SH/dll_01A8_shkillermushroom | 100.0000 | 79.4975 | -20.5025 |
| main/main/dll/cutcam | 99.8728 | 79.7070 | -20.1658 |
| main/main/dll/ARW/dll_02A6_arwsquadron | 100.0000 | 79.9973 | -20.0027 |
| main/main/snowclaw | 100.0000 | 80.3167 | -19.6833 |
| main/main/dll/CC/dll_0188_cclightfoot | 100.0000 | 80.3610 | -19.6390 |
| main/main/dll/dll_00FE_magicplant | 100.0000 | 80.7388 | -19.2612 |
| main/main/dll/dll_00F0_warppoint | 100.0000 | 80.8028 | -19.1972 |
| main/main/dll/VF/dll_0216_vfplevelcontrol | 100.0000 | 80.8854 | -19.1146 |
| main/main/dll/dll_017F_moonseedbush | 100.0000 | 81.3284 | -18.6716 |
| main/main/dll/WC/dll_0297_wctemplebri | 100.0000 | 81.4000 | -18.6000 |
| main/main/dll/dll_01CE_dll1ce | 100.0000 | 81.5400 | -18.4600 |
| main/main/dll/dll_013A_visanimator | 100.0000 | 81.5478 | -18.4522 |
| main/main/dll/dll_017D_rollingbarrel | 100.0000 | 81.6367 | -18.3633 |
| main/main/dll/fireflygroup | 100.0000 | 81.7300 | -18.2700 |
| main/main/dll/CC/dll_0185_ccgasvent | 100.0000 | 81.8442 | -18.1558 |
| main/main/dll/ARW/dll_029D_arwarwinggu | 100.0000 | 81.9671 | -18.0329 |
| main/main/dll/dll_0003_checkpoint | 99.3938 | 81.3705 | -18.0233 |
| main/main/dll/SC/dll_01BB_sctotembond | 100.0000 | 82.1324 | -17.8676 |
| main/main/mm | 99.5834 | 81.7241 | -17.8593 |
| main/main/dll/dll_801ac01c | 100.0000 | 82.1583 | -17.8417 |
| main/main/dll/WC/dll_0290_wcpushblock | 100.0000 | 82.1670 | -17.8330 |
| main/main/dll/DIM/dll_01CB_dimwooddoor2 | 100.0000 | 82.4581 | -17.5419 |
| main/main/dll/dll_0173_linklevcontrol | 100.0000 | 82.5784 | -17.4216 |
| main/main/dll/dll_02B1_cmbsrc | 100.0000 | 82.9992 | -17.0008 |
| main/main/dll/CC/dll_0186_ccgasventcontrol | 100.0000 | 83.0330 | -16.9670 |
| main/main/dll/SH/SHthorntail | 100.0000 | 83.2576 | -16.7424 |
| main/main/dll/CF/dll_0148_cfguardian | 100.0000 | 84.1805 | -15.8195 |
| main/main/dll/WC/dll_0291_wctile | 100.0000 | 84.2817 | -15.7183 |
| main/main/dll/dll_010C_lanternfirefly | 100.0000 | 84.4412 | -15.5588 |
| main/main/dll/ARW/dll_02A5_arwgenerato | 100.0000 | 84.5118 | -15.4882 |
| main/main/dll/NW/nwmammothgroup | 100.0000 | 84.7063 | -15.2937 |
| main/main/dll/kooshy | 100.0000 | 85.0698 | -14.9302 |
| main/main/crcloudrace | 100.0000 | 85.1061 | -14.8939 |
| main/main/dll/dll_0200_dll200 | 100.0000 | 85.2343 | -14.7657 |
| main/main/dll/dll_010A_fallladders | 100.0000 | 85.3920 | -14.6080 |
| main/main/fileio | 100.0000 | 85.6233 | -14.3767 |
| main/main/dll/DIM/dimgut2group | 100.0000 | 85.8364 | -14.1636 |
| main/main/dll/DR/dll_0252_ktlazerwall | 100.0000 | 85.8575 | -14.1425 |
| main/main/dll/dll_024D_bossdrakor | 99.5893 | 85.5837 | -14.0056 |
| main/main/dll/dll_01AA_bombplantspore | 100.0000 | 86.1777 | -13.8223 |
| main/main/dll/duster_wb | 100.0000 | 86.2121 | -13.7879 |
| main/main/dll/dll_0271_drakorhoverpad | 100.0000 | 86.2241 | -13.7759 |
| main/main/dll/ARW/dll_029A_arwarwing | 100.0000 | 86.2676 | -13.7324 |
| main/main/modelEngine | 100.0000 | 86.3317 | -13.6683 |
| main/main/dll/dll_801c0bf8 | 98.6299 | 85.2597 | -13.3701 |
| main/main/objprint | 99.9558 | 86.7247 | -13.2311 |
| main/main/dll/dll_0010_uicontroller | 100.0000 | 87.2586 | -12.7414 |
| main/main/dll/MMP/dll_0182_mmpmoonrock | 100.0000 | 87.3506 | -12.6494 |
| main/main/audio/synth_channel | 100.0000 | 87.5556 | -12.4444 |
| main/main/dll/fallladdersgroup | 100.0000 | 87.5778 | -12.4222 |
| main/main/dll/dll_00CE_dllce | 100.0000 | 87.6225 | -12.3775 |
| main/main/dll/duster | 100.0000 | 87.9461 | -12.0539 |
| main/main/dll/snowworm | 100.0000 | 87.9695 | -12.0305 |
| main/main/dll/dll_0039_dummy39 | 100.0000 | 88.0233 | -11.9767 |
| main/main/dll/DR/dll_0258_drcloudrunner | 99.7540 | 87.7828 | -11.9713 |
| main/main/dll/dll_0157_spiritdoorspirit | 100.0000 | 88.2917 | -11.7083 |
| main/main/dll/dll_000F_unk | 100.0000 | 88.2923 | -11.7077 |
| main/main/dll/dll_00ED_collectible | 100.0000 | 88.3457 | -11.6543 |
| main/main/dll/dll_0117_appleontree | 100.0000 | 88.3529 | -11.6471 |
| main/main/dll/MMP/dll_0183_mmpgyservent | 100.0000 | 88.4382 | -11.5618 |
| main/main/dll/cfdoorlightgroup | 100.0000 | 89.0893 | -10.9107 |
| main/main/dll/dll_0107_unused | 100.0000 | 89.1886 | -10.8114 |
| main/main/dll/DF/dll_0235_dfptargetblock | 100.0000 | 89.2309 | -10.7691 |
| main/main/dll/SH/dll_01AC_shqueenearthwalker | 100.0000 | 89.3002 | -10.6998 |
| main/main/objHitReact | 100.0000 | 89.3645 | -10.6355 |
| main/main/dll/dll_003C_tumbleweedbush | 99.8834 | 89.2541 | -10.6294 |
| main/main/dll/firecrawler | 100.0000 | 89.4555 | -10.5445 |
| main/main/dll/dll_0047_cameramodeteststrength | 100.0000 | 89.6374 | -10.3626 |
| main/main/newclouds | 100.0000 | 89.8743 | -10.1257 |
| main/main/dll/dll_0130_areafxemit | 100.0000 | 90.3232 | -9.6768 |
| main/main/dll/dll_018C_mmshshrine | 100.0000 | 90.4640 | -9.5360 |
| main/main/dll/seqobj11e | 100.0000 | 90.5995 | -9.4005 |
| main/main/dll/dll_0273_firepipe | 100.0000 | 90.9327 | -9.0673 |
| main/main/worldplanet_lighting | 100.0000 | 91.2387 | -8.7613 |
| main/main/dll/skeetla | 99.7052 | 91.0786 | -8.6265 |
| main/main/audio/snd3dgroup | 100.0000 | 91.4300 | -8.5700 |
| main/main/dll/dll_0266_kytesmum | 100.0000 | 91.7997 | -8.2003 |
| main/main/dll/dll_000B_dll0b | 98.8607 | 90.7162 | -8.1444 |
| main/main/dll/dll_0119_coldwatercontrol | 100.0000 | 91.8795 | -8.1205 |
| main/main/dll/dll_01A9_bombplant | 100.0000 | 91.9378 | -8.0622 |
| main/main/dll/dll_0015_curves | 99.6533 | 91.6076 | -8.0457 |
| main/main/dll/dll_0158_gunpowderbarrel | 100.0000 | 92.4408 | -7.5592 |
| main/main/dll/SH/dll_01AE_shlevelcontrol | 100.0000 | 92.5453 | -7.4547 |
| main/main/dll/camshipbattle5c | 99.7560 | 92.5326 | -7.2234 |
| main/main/shader | 98.9392 | 92.0709 | -6.8682 |
| main/main/dll/dll_02A0_ring | 100.0000 | 93.4272 | -6.5728 |
| main/main/audio | 100.0000 | 93.4540 | -6.5460 |
| main/main/dll/dll_00CA_icebaddie | 100.0000 | 93.5470 | -6.4530 |
| main/main/dll/pathcamgroup | 100.0000 | 94.0781 | -5.9219 |
| main/main/dll/newseqobjgroup | 100.0000 | 94.1978 | -5.8022 |
| main/main/dll/dll_801e991c | 100.0000 | 94.2054 | -5.7946 |
| main/main/audio/synth | 100.0000 | 94.3344 | -5.6656 |
| main/main/dll/DIM/dll_01E2_dimbosstonsil | 100.0000 | 94.3782 | -5.6218 |
| main/main/audio/voice_alloc | 99.8628 | 94.3476 | -5.5152 |
| main/main/modellight | 99.9833 | 94.5821 | -5.4012 |
| main/main/dll/WM/dll_0211_wmwallcrawler | 100.0000 | 94.7003 | -5.2997 |
| main/main/dll/dll_8011d918 | 100.0000 | 94.7368 | -5.2632 |
| main/main/dll/DR/dll_0261_drlasercannon | 99.4782 | 94.3216 | -5.1565 |
| main/main/dll/dll_0242_dbstealerworm | 99.9161 | 94.8762 | -5.0398 |
| main/main/objseq | 99.7434 | 94.7181 | -5.0253 |
| main/main/dll/DR/dll_0257_drearthwarrior | 99.8439 | 94.9341 | -4.9098 |
| main/main/dll/dll_0272_hightop | 100.0000 | 95.0953 | -4.9047 |
| main/main/dll/DF/dll_0233_dfpstatue1 | 100.0000 | 95.1807 | -4.8193 |
| main/main/dll/tricky_flameguard | 99.9461 | 95.1526 | -4.7935 |
| main/main/newshadows | 97.9941 | 93.2277 | -4.7664 |
| main/main/audio/mcmd_exec | 99.6306 | 94.9170 | -4.7136 |
| main/main/dll/dll_004A_cameramodeshipbattle | 99.7038 | 95.1916 | -4.5122 |
| main/main/dll/WC/dll_028D_wclevelcont | 100.0000 | 95.7487 | -4.2513 |
| main/main/dll/player | 99.8379 | 95.6264 | -4.2115 |
| main/main/dll/Hcurves | 99.6559 | 95.5111 | -4.1448 |
| main/main/dll/dll_00EF_pushable | 100.0000 | 96.3079 | -3.6921 |
| main/main/dll/dll_0096_dll96func0 | 100.0000 | 96.4500 | -3.5500 |
| main/main/objprint_dolphin | 99.5826 | 96.0952 | -3.4874 |
| main/main/dll/dll_00E4_flamethrowerspe | 100.0000 | 96.6500 | -3.3500 |
| main/main/dll/dll_0093_dll93func0 | 100.0000 | 96.6667 | -3.3333 |
| main/main/dll/dll_0013_waterfx | 99.8671 | 96.5743 | -3.2928 |
| main/main/dll/animobjd2 | 99.1506 | 95.9151 | -3.2355 |
| main/track/intersect | 100.0000 | 96.8889 | -3.1111 |
| main/main/dll/DIM/dll_0256_dimsnowhorn1 | 100.0000 | 96.8979 | -3.1021 |
| main/main/dll/dll_004E_cameramodeworldmap | 99.8534 | 96.7666 | -3.0868 |
| main/main/sky | 99.8372 | 96.9997 | -2.8375 |
| main/main/dll/trickyfollow | 99.8147 | 96.9942 | -2.8206 |
| main/main/voxmaps | 99.5590 | 96.7568 | -2.8022 |
| main/main/dll/picmenu | 100.0000 | 97.2010 | -2.7990 |
| main/main/dll/attractmovie | 100.0000 | 97.2072 | -2.7928 |
| main/main/dll/dll_02B5_timer | 100.0000 | 97.2096 | -2.7904 |
| main/main/atan2f | 98.7298 | 96.0081 | -2.7218 |
| main/main/dll/dll_0056_cameramodearwing | 99.8479 | 97.1663 | -2.6815 |
| main/main/dll/dll_80136a40 | 99.1092 | 96.5304 | -2.5788 |
| main/main/dll/dll_0032_titlescreeninit | 100.0000 | 97.5015 | -2.4985 |
| main/main/dll/dll_00F5_sidekickball | 100.0000 | 97.5680 | -2.4320 |
| main/main/dll/ARW/dll_029F_arwbombcoll | 100.0000 | 97.6175 | -2.3825 |
| main/main/dll/dll_0017_savegame | 99.7631 | 97.4521 | -2.3110 |
| main/main/tex_dolphin | 99.9727 | 97.6931 | -2.2796 |
| main/main/dll/laserturretgroup | 100.0000 | 97.7680 | -2.2320 |
| main/main/dll/dll_0045_camTalk | 99.9591 | 97.7451 | -2.2141 |
| main/main/dll/DR/dll_0250_ktrex | 100.0000 | 97.8409 | -2.1591 |
| main/main/dll/frontend_control | 100.0000 | 97.8855 | -2.1145 |
| main/main/dll/dll_02AD_softbody | 100.0000 | 97.9618 | -2.0382 |
| main/main/audio/synth_queue | 99.7566 | 97.7389 | -2.0177 |
| main/main/objhits | 99.5566 | 97.5795 | -1.9771 |
| main/main/dll/DF/dll_022B_dfptorch | 100.0000 | 98.1300 | -1.8700 |
| main/main/dll/NW/dll_01A2_nwtricky | 100.0000 | 98.1304 | -1.8696 |
| main/main/dll/DIM/dll_01DE_dim2lavacontrol | 100.0000 | 98.1448 | -1.8552 |
| main/main/dll/dll_0046_cameramodedebug | 100.0000 | 98.1799 | -1.8201 |
| main/main/dll/cloudaction | 100.0000 | 98.2189 | -1.7811 |
| main/main/dll/dll_00DE_baddieinterestp | 100.0000 | 98.2407 | -1.7593 |
| main/main/dll/dll_024E_drakordthornbush | 100.0000 | 98.3441 | -1.6559 |
| main/main/dll/LGT/dll_02AB_lgtprojectedlight | 100.0000 | 98.3660 | -1.6340 |
| main/main/audio/voice_manage | 100.0000 | 98.4296 | -1.5704 |
| main/main/camera | 99.7639 | 98.2861 | -1.4778 |
| main/main/dll/dll_028B | 100.0000 | 98.5294 | -1.4706 |
| main/main/dll/dll_0138_groundanimator | 99.4356 | 97.9693 | -1.4663 |
| main/main/dll/dll_023F_dbegg | 100.0000 | 98.5857 | -1.4143 |
| main/main/maketex | 99.9532 | 98.5706 | -1.3827 |
| main/main/dll/dll_0123_fuelcell | 100.0000 | 98.6375 | -1.3625 |
| main/main/dll/WM/dll_0209_wmlevelcontrol | 100.0000 | 98.6942 | -1.3058 |
| main/main/dll/SH/dll_01B1_shstaff | 100.0000 | 98.7117 | -1.2883 |
| main/main/dll/dll_0098_dll98func0 | 100.0000 | 98.7595 | -1.2405 |
| main/main/dll/dll_02BC_andross | 99.8201 | 98.6141 | -1.2060 |
| main/main/dll/dll_0049_cameramodecombat | 100.0000 | 98.7962 | -1.2038 |
| main/main/dll/tricky_substates | 99.9608 | 98.7689 | -1.1919 |
| main/main/dll/dll_3e | 100.0000 | 98.8420 | -1.1580 |
| main/main/audio/sal_dsp | 100.0000 | 98.8571 | -1.1429 |
| main/main/dll/SB/dll_01EF_sbcloudball | 100.0000 | 98.8923 | -1.1077 |
| main/main/dll/dll_00E2_staff | 99.7356 | 98.6813 | -1.0543 |
| main/main/dll/dll_0052_cameramodeforcebehind | 100.0000 | 98.9511 | -1.0489 |
| main/main/dll/WM/dll_0207_wmworm | 100.0000 | 98.9840 | -1.0160 |
| main/main/dll/dll_0126_trigger | 99.8561 | 98.8547 | -1.0014 |
| main/main/dll/dll_02BE_androssbrain | 100.0000 | 99.0222 | -0.9778 |
| main/main/dll/scshgroup | 100.0000 | 99.0412 | -0.9588 |
| main/main/dll/dll_018F_ecshshrine | 100.0000 | 99.0542 | -0.9458 |
| main/main/dll/dll_0069_dll69func0 | 99.8726 | 98.9490 | -0.9236 |
| main/main/dll/dll_00F4_doorf4 | 100.0000 | 99.0866 | -0.9134 |
| main/main/dll/dll_0053_cameramodecloudrunner | 100.0000 | 99.1071 | -0.8929 |
| main/main/dll/dll_009C_dll9cfunc0 | 100.0000 | 99.1438 | -0.8562 |
| main/main/dll/dll_013B_wallanimator | 100.0000 | 99.1722 | -0.8278 |
| main/main/dll/DIM/dll_01DD_dim2icicle | 100.0000 | 99.1954 | -0.8046 |
| main/main/worldplanet | 99.4555 | 98.6553 | -0.8002 |
| main/main/dll/SB/dll_01E8_sbgalleon | 100.0000 | 99.2191 | -0.7809 |
| main/main/dll/dll_01D6_dll1d6 | 100.0000 | 99.2335 | -0.7665 |
| main/main/dll/tumbleweedbush | 100.0000 | 99.2518 | -0.7482 |
| main/main/dll/DF/dll_0175_dfropenode | 99.9100 | 99.1700 | -0.7400 |
| main/main/dll/LGT/dll_02AC_lgtcontrollight | 100.0000 | 99.2727 | -0.7273 |
| main/main/dll/mmp_cratercritter | 100.0000 | 99.3197 | -0.6803 |
| main/main/dll/dll_0000_gameui | 99.7396 | 99.0757 | -0.6639 |
| main/main/audio/hw_stream | 100.0000 | 99.3367 | -0.6633 |
| main/main/dll/weevil | 100.0000 | 99.3687 | -0.6313 |
| main/main/audio/synth_channel_scale | 99.4686 | 98.9112 | -0.5575 |
| main/main/dll/warppad | 100.0000 | 99.4592 | -0.5408 |
| main/main/dll/dll_0269_explodeplan | 100.0000 | 99.4805 | -0.5195 |
| main/main/dll/dll_0262_drakormissile | 100.0000 | 99.4922 | -0.5078 |
| main/main/render | 97.7715 | 97.3112 | -0.4602 |
| main/main/dll/n_options | 100.0000 | 99.5541 | -0.4459 |
| main/main/dll/obj_movelib | 100.0000 | 99.5935 | -0.4065 |
| main/main/dll/dll_0110_door | 100.0000 | 99.6393 | -0.3607 |
| main/main/audio/synth_seq_dispatch | 100.0000 | 99.6497 | -0.3503 |
| main/main/dll/dll_bb | 100.0000 | 99.6584 | -0.3416 |
| main/main/dll/dll_01A7_ediblemushroom | 100.0000 | 99.6598 | -0.3402 |
| main/main/dll/dll_011D_treasurechest | 100.0000 | 99.6698 | -0.3302 |
| main/main/dll/dll_029B_arwingandrossstuff | 100.0000 | 99.6727 | -0.3273 |
| main/main/dll/dll_012C_transporter | 100.0000 | 99.6791 | -0.3209 |
| main/main/dll/dll_00C4_tricky | 100.0000 | 99.6979 | -0.3021 |
| main/main/dll/dll_013C_xyzanimator | 99.9580 | 99.6603 | -0.2977 |
| main/main/dll/dll_00DF_hagabon | 100.0000 | 99.7291 | -0.2709 |
| main/main/dll/DIM/dll_01E5_dimbossspit | 100.0000 | 99.7363 | -0.2637 |
| main/main/dll/DIM/dll_00C7_dim2roofrub | 100.0000 | 99.7550 | -0.2450 |
| main/main/dll/dll_00C9_enemy | 100.0000 | 99.7737 | -0.2263 |
| main/main/pad | 99.6415 | 99.4263 | -0.2151 |
| main/main/dll/dll_0104_smallbasket | 100.0000 | 99.8238 | -0.1762 |
| main/main/dll/dll_0019_dll19func0 | 100.0000 | 99.8318 | -0.1682 |
| main/main/dll/dll_02B3_vortex | 99.8681 | 99.7229 | -0.1451 |
| main/main/dll/dll_002E_moveLib | 100.0000 | 99.8606 | -0.1394 |
| main/main/dll/dll_0103_curvefish | 100.0000 | 99.8667 | -0.1333 |
| main/main/dll/tumbleweedgroup | 100.0000 | 99.8943 | -0.1057 |
| main/main/dll/dll_00D3_staffAction | 100.0000 | 99.8946 | -0.1054 |
| main/main/dll/dll_02A3 | 100.0000 | 99.9005 | -0.0995 |
| main/main/dll/dll_02AE_waterflowwe | 100.0000 | 99.9048 | -0.0952 |
| main/main/dll/dll_0136_waveanimator | 100.0000 | 99.9085 | -0.0915 |
| main/main/dll/DR/dll_0251_ktrexfloorswitch | 100.0000 | 99.9114 | -0.0886 |
| main/main/dll/dll_00A6_dlla6func0 | 100.0000 | 99.9149 | -0.0851 |
| main/main/dll/dll_008E_dll8efunc0 | 100.0000 | 99.9195 | -0.0805 |
| main/main/dll/dll_009A_dll9afunc0 | 100.0000 | 99.9409 | -0.0591 |
| main/main/audio/voice_id | 100.0000 | 99.9580 | -0.0420 |
| main/main/trig | 99.7798 | 99.7542 | -0.0256 |
| main/main/dll/dll_00E5_shield | 99.4638 | 99.4396 | -0.0242 |

### Re-promotion queue
Every demoted unit is a re-promotion candidate: flip back to MatchingFor and let the
DOL sha judge; units needing a hack to match stay NonMatching per CLAUDE.md policy.
