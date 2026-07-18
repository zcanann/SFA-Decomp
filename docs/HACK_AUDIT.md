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

## Wave 1 (partial - agents interrupted; ~1,536 of 3,209 hack lines removed)

Overall fuzzy 99.841 -> 95.171 (post-demotion report). Every unit still compiles;
DOL byte-identical via 22 demotions to NonMatching (retail objs link in their place).

### Demoted units (were MatchingFor; re-promotion candidates once re-matched or TU-resplit)

- main/dll/dll_0094_dll94func0.c
- main/dll/dll_001D_effect4.c
- main/dll/dll_00CB_dllcb.c
- main/dll/dll_016C_dll16c.c
- main/dll/dll_016A_crrockfall.c
- main/dll/grimblegroup.c
- main/dll/dll_02BB_gflevelcon.c
- main/dll/dll_003B_menu.c
- main/dll/ARW/dll_02A6_arwsquadron.c
- main/dll/DIM/dimgut2group.c
- main/dll/dll_0271_drakorhoverpad.c
- main/dll/ARW/dll_029A_arwarwing.c
- main/dll/dll_000F_unk.c
- main/dll/DF/dll_0235_dfptargetblock.c
- main/dll/dll_00CA_icebaddie.c
- main/dll/WM/dll_0211_wmwallcrawler.c
- main/dll/newseqobjgroup.c
- main/dll/DIM/dll_00C7_dim2roofrub.c
- main/dll/dll_00D3_staffAction.c
- main/dll/dll_0028_effect15.c
- main/dll/dll_00E1_wispbaddie.c
- main/dll/magicplant.c

### Per-unit fuzzy impact

| Unit | Before | After | Delta |
|---|---|---|---|
| main/main/dll/dll_0094_dll94func0 | 100.0000 | 7.6017 | -92.3983 |
| main/main/dll/dll_001D_effect4 | 100.0000 | 37.6655 | -62.3345 |
| main/main/dll/dll_00CB_dllcb | 100.0000 | 45.7133 | -54.2867 |
| main/main/dll/DIM/dll_01CA_dimexplosion | 100.0000 | 46.7400 | -53.2600 |
| main/main/textrender | 99.4267 | 51.5785 | -47.8483 |
| main/main/track_dolphin | 99.0354 | 57.1895 | -41.8458 |
| main/main/dll/dll_02C0_front | 99.7227 | 58.9538 | -40.7689 |
| main/main/dll/dll_016C_dll16c | 100.0000 | 59.5588 | -40.4412 |
| main/main/lightmap | 99.7713 | 60.9359 | -38.8354 |
| main/main/dll/dll_016A_crrockfall | 100.0000 | 62.5634 | -37.4366 |
| main/main/dll/grimblegroup | 100.0000 | 63.0332 | -36.9668 |
| main/main/model | 99.7706 | 63.0566 | -36.7140 |
| main/main/dll/expgfx | 99.2022 | 63.0008 | -36.2014 |
| main/main/dll/dll_02BB_gflevelcon | 100.0000 | 65.1733 | -34.8267 |
| main/main/rcp_dolphin | 99.7276 | 68.2845 | -31.4431 |
| main/main/pi_dolphin | 98.6446 | 68.5846 | -30.0600 |
| main/main/object | 99.9370 | 71.5331 | -28.4040 |
| main/main/objlib | 99.9354 | 72.3720 | -27.5633 |
| main/main/dll/dll_003B_menu | 100.0000 | 77.3333 | -22.6667 |
| main/main/gameloop | 99.7745 | 78.0871 | -21.6874 |
| main/main/dll/ARW/dll_02A6_arwsquadron | 100.0000 | 79.9973 | -20.0027 |
| main/main/dll/DIM/dimgut2group | 100.0000 | 85.8364 | -14.1636 |
| main/main/dll/dll_0271_drakorhoverpad | 100.0000 | 86.2241 | -13.7759 |
| main/main/dll/ARW/dll_029A_arwarwing | 100.0000 | 86.2676 | -13.7324 |
| main/main/objprint | 99.9558 | 86.7247 | -13.2311 |
| main/main/dll/dll_000F_unk | 100.0000 | 88.2923 | -11.7077 |
| main/main/dll/DF/dll_0235_dfptargetblock | 100.0000 | 89.2309 | -10.7691 |
| main/main/shader | 98.9392 | 92.1053 | -6.8339 |
| main/main/audio | 100.0000 | 93.4540 | -6.5460 |
| main/main/dll/dll_00CA_icebaddie | 100.0000 | 93.5470 | -6.4530 |
| main/main/modellight | 99.9833 | 94.5821 | -5.4012 |
| main/main/dll/WM/dll_0211_wmwallcrawler | 100.0000 | 94.7003 | -5.2997 |
| main/main/dll/newseqobjgroup | 100.0000 | 94.7887 | -5.2113 |
| main/main/dll/dll_0242_dbstealerworm | 99.9161 | 94.8762 | -5.0398 |
| main/main/objseq | 99.7434 | 94.7181 | -5.0253 |
| main/main/newshadows | 97.9941 | 93.2277 | -4.7664 |
| main/main/dll/player | 99.8379 | 95.6264 | -4.2115 |
| main/main/dll/Hcurves | 99.6559 | 95.5111 | -4.1448 |
| main/main/objprint_dolphin | 99.5826 | 96.0952 | -3.4874 |
| main/main/sky | 99.8372 | 96.9997 | -2.8375 |
| main/main/voxmaps | 99.5590 | 96.7568 | -2.8022 |
| main/main/dll/dll_80136a40 | 99.1092 | 96.5304 | -2.5788 |
| main/main/dll/dll_0045_camTalk | 99.9591 | 97.7451 | -2.2141 |
| main/main/dll/tricky_substates | 99.9608 | 98.7689 | -1.1919 |
| main/main/dll/dll_0000_gameui | 99.7396 | 99.4265 | -0.3132 |
| main/main/dll/dll_00C4_tricky | 100.0000 | 99.6979 | -0.3021 |
| main/main/dll/dll_013C_xyzanimator | 99.9580 | 99.6603 | -0.2977 |
| main/main/dll/DIM/dll_00C7_dim2roofrub | 100.0000 | 99.7550 | -0.2450 |
| main/main/dll/dll_00D3_staffAction | 100.0000 | 99.8946 | -0.1054 |

## Remaining

~1,670 hack lines still present across src/main + src/track; purge wave 2 continues.
Re-promotion pass planned for demoted units whose objects prove still byte-identical.
Overall fuzzy now 95.18889.
