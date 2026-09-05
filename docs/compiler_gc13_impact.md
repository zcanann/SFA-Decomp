# GC/1.3 game-code migration impact

Measured against staging commit `ec46541f3cf42c3702ca99542cec55c581263e17` on 2026-09-05, EN v1.0 (`GSAE01`). This is a compiler-only migration-cost measurement for the current reconstructed source, not evidence of Rare's historical compiler.

Later source cleanup and whole-TU migrations are tracked in [compiler_gc13_cleanup.md](compiler_gc13_cleanup.md). The measurements below retain their original source/config baseline.

## Scope and method

- Recompiled 787 MWCC game units twice, using the configured compiler and then `GC/1.3`. The compiler changes in 777 units; 10 already use 1.3 and serve as controls.
- Preserved every source file, flag, include, and existing section-realignment postprocessor. Used the real Ninja compile commands, separate output directories, and checked every compiler exit status.
- Left SDK, MSL, MusyX, and the ProDG decompressor unchanged. The game reporting category includes 11 library math units and the ProDG unit; these 12 entries are excluded from migration.
- All 787 scratch baseline objects agree with the normal build after ignoring compiler metadata and anonymous-symbol numbering. Source-file hashes remained unchanged during the audit.
- Generated full baseline and candidate objdiff reports. Compared object contents, symbol offsets, and relocations with `tools/obj_equal.py`.

## Results

| Measure | Configured baseline | GC/1.3 candidate |
| --- | ---: | ---: |
| Game-unit compile failures | 0 | 0 |
| Exact functions in the 787 tested units | 7,990 / 8,161 | 7,900 / 8,161 |
| Exact functions in the full game reporting category | 8,041 / 8,213 | 7,951 / 8,213 |
| Game-category fuzzy match | 99.803240% | 99.701096% |
| Game-category exact code bytes | 2,213,208 | 2,141,296 |
| Game-category exact data bytes | 982,099 | 978,227 |
| Whole-project fuzzy match | 99.826180% | 99.736404% |

90 previously exact functions lose their match, across 61 units; none become newly exact. Their complete sizes total 71,912 bytes. This is the amount of code no longer counted as exact, **not** the number of differing instruction bytes.

707 of 787 objects remain equivalent under the normalized comparison. 80 differ beyond `.comment` and anonymous-symbol numbering: 66 units lose fuzzy match, while 14 have equal fuzzy scores but different pooled-data relocation representations. No unit improves its fuzzy score. Seven of those 14 are currently source-linked; retaining their GC/1.3 objects in the fallback link below proves those seven are link-neutral in this build.

The full report's `complete_*` fields retain the existing configuration declarations. They must not be read as a fresh certification of matching status after the compiler change.

## Link and checksum validation

- Baseline `python3 configure.py --matching` plus `ninja` passed in 15.84 seconds; `ninja all_source` passed in 14.43 seconds. Both Ninja invocations had a 30-second timeout.
- Replaced the 714 game-source objects actually used by the current matching link with their freshly rebuilt baseline equivalents. The DOL remained byte-identical to retail.
- Repeated with the 714 GC/1.3 candidates, preserving the GC/1.3.2 linker and all other inputs. Linking succeeded, but the DOL grew by 992 bytes to 3,399,968 bytes and failed retail identity (SHA-1 `2e0dcd1acc50739df469f2f1528138f53cd6a67e`).
- Replaced the 51 currently source-linked units whose fuzzy score regressed with their existing retail reference objects. Kept all remaining GC/1.3 game objects. This linked to the exact 3,398,976-byte retail DOL, SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`.
- Thus a compiler migration with 51 whole-TU `NonMatching` fallbacks can keep the strict build working. Those units contain 262,292 bytes of text and 27,833 bytes of assigned data; their source remains compilable and available for recovery. No compiler settings or matching declarations were changed in this audit.

## Reproduction and detailed results

Run `python3 tools/compiler_impact.py --compiler GC/1.3 --output build/compiler_impact/<new-directory> --jobs 6` after the normal baseline build. The output manifest records every compile command, object path, source hash, object difference, function score, and aggregate report. The tool writes only scratch build artifacts. The three link substitutions above were checked separately using the normal Ninja link order and flags.

The original local run is under `build/compiler_impact/gc13_ec46541f3c/`, including baseline/candidate reports, the compiler-command manifest, three linked DOLs, link logs, and checksum results. The complete function-loss list is [compiler_gc13_function_losses.csv](compiler_gc13_function_losses.csv).

## Units requiring retail fallback in the verified link

These are existing source paths, listed for a possible migration; this report does not apply the changes.

- `src/dlls/engine/15/15.c`
- `src/dlls/engine/25/25.c`
- `src/dlls/objects/201_Baddie/Baddie.c`
- `src/dlls/objects/209_TumbleWeedB/TumbleWeedB.c`
- `src/dlls/objects/226/226.c`
- `src/dlls/objects/237/237.c`
- `src/dlls/objects/239/239.c`
- `src/dlls/objects/280_Duster/Duster.c`
- `src/dlls/objects/294/294.c`
- `src/dlls/objects/364/364.c`
- `src/dlls/objects/414/414.c`
- `src/dlls/objects/424_SH_killermu/SH_killermu.c`
- `src/dlls/objects/429_SH_thorntai/SHthorntail.c`
- `src/dlls/objects/430_SH_LevelCon/SH_LevelCon.c`
- `src/dlls/objects/458_DIMExplosio/DIMExplosio.c`
- `src/dlls/objects/468_WORLDAstero/WORLDAstero.c`
- `src/dlls/objects/482_DIM_BossTon/DIM_BossTon.c`
- `src/dlls/objects/483_DIM_BossGut/DIM_BossGut.c`
- `src/dlls/objects/525_WM_seqpoint/WM_seqpoint.c`
- `src/dlls/objects/529/529.c`
- `src/dlls/objects/544/544.c`
- `src/dlls/objects/547_VFP_corepla/VFP_corepla.c`
- `src/dlls/objects/557_DFP_seqpoin/DFP_seqpoin.c`
- `src/dlls/objects/578_DBstealerwo/DBstealerwo.c`
- `src/dlls/objects/591_KT_RexLevel/KT_RexLevel.c`
- `src/dlls/objects/592_KT_Rex/KT_Rex.c`
- `src/dlls/objects/593_KT_RexFloor/KT_RexFloor.c`
- `src/dlls/objects/596_KT_Fallingr/KT_Fallingr.c`
- `src/dlls/objects/597/597.c`
- `src/dlls/objects/598_DIMSnowHorn/DIMSnowHorn.c`
- `src/dlls/objects/601_SB_Cloudrun/SB_Cloudrun.c`
- `src/dlls/objects/605_CRCloudRace/CRCloudRace.c`
- `src/dlls/objects/606/606.c`
- `src/dlls/objects/609_DR_LaserCan/DR_LaserCan.c`
- `src/dlls/objects/611_GM_MazeWell/GM_MazeWell.c`
- `src/dlls/objects/614_KytesMum/KytesMum.c`
- `src/dlls/objects/619_DR_Chimmey/DR_Chimmey.c`
- `src/dlls/objects/620/620.c`
- `src/dlls/objects/622/622.c`
- `src/dlls/objects/623/623.c`
- `src/dlls/objects/626/626.c`
- `src/dlls/objects/627_FirePipe/FirePipe.c`
- `src/dlls/objects/643_DR_BarrelGr/DR_BarrelGr.c`
- `src/dlls/objects/646_SPShopKeepe/SPShopKeepe.c`
- `src/dlls/objects/662_WCTempleDia/WCTempleDia.c`
- `src/dlls/objects/663_WCTempleBri/WCTempleBri.c`
- `src/main/gameloop.c`
- `src/main/gameloop_main.c`
- `src/main/modelEngine.c`
- `src/main/objlib.c`
- `src/main/thp/n_options.c`
