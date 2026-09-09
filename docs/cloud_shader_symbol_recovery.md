# Cloud and shader symbol identities across retail versions

PAL cloud rendering and shader setup had exact normalized code but incomplete
small-data matches. Six EN shader labels collided with unrelated PAL `.sdata`
objects, while the cloud override pointer had only a regional address label.
The shared source now uses unit-specific names at the independently verified
addresses in EN, EN rev1, JP and PAL rev1.

## Small-data identity

`Rcp_ResetTextureStageState` provides unique paired r13-relative stores for all
eleven reset-only shader globals. They occupy EN `803DCD48..803DCD68` and PAL
`803DE700..803DE720`. The names describe their parallel initialization beside
the active texture-stage state. No retail reads are known; this does not claim
a recovered save/restore API. Declaration order, widths and storage are retained.

The PAL cloud link also required naming `saveGameGetEnvState` at `800E8950`.
Seventeen calls in independently matched functions, including cloud, sky and
shader consumers, all map EN `800E84F8` to that target. Both getters return the
save-data base plus `0x6A8`; the regionally moved base is the only instruction
operand difference. The previous PAL symbol was `fn_800E8950`.

`renderClouds` and `cloudaction_initialise` witness the first word of the existing
eight-byte cloud override storage. It is now `gCloudOverrideObjectStorage`, with
the existing `gCloudOverrideObject` view retained. This rename does not establish
a role for the second word.

| Version | Cloud override storage |
| --- | --- |
| EN | `803DD1F0` |
| EN rev1 | `803DDE70` |
| JP | `803DD310` |
| PAL rev1 | `803DEBA8` |

The SDA audit previously accepted an alternate regional label even when source
used a missing or conflicting EN identifier. It now resolves source-used names
across sections and reports the actual configured binding. Only names unused by
source may fall back to a regional address label. The regression test covers a
cross-section collision, a missing source name, and the valid unused-name case.

## Three false MSL names

The cloud descriptor's callbacks 10, 11 and 12 were incorrectly named
`__end_critical_region`, `__begin_critical_region` and `__kill_critical_regions`.
Each is a four-byte `blr`, adjacent to two other cloud no-op callbacks.
Scanning retail code and aligned data finds no direct branch callers and one
pointer to each function, in these descriptor words:

| Version | Callback 10 | Callback 11 | Callback 12 |
| --- | --- | --- | --- |
| EN | `8030F820` | `8030F824` | `8030F828` |
| EN rev1 | `803103E0` | `803103E4` | `803103E8` |
| JP | `8030F940` | `8030F944` | `8030F948` |
| PAL rev1 | `80310FF0` | `80310FF4` | `80310FF8` |

They are now `cloudaction_func10_nop`, `cloudaction_func11_nop` and
`cloudaction_func12_nop`, following the existing numbered callback convention.
The incorrect cloud-only `critical_regions.gamecube.h` is removed. The separate
MSL declarations and unbuilt reference `signal.c` remain; this is evidence about
these three cloud callbacks, not a general identification of all MSL stubs.

## Constant retention exposed by the full link

The reconstructed `addWarpedRingTevStages` reads its axes and matrix through
offsets from `sEnvMapBumpIndMtx`. EN already explicitly retains
`sWarpedRingRotAxes` and `sWarpedRingIndMtx`; the secondary configurations lacked
those entries. Substituting shader source into EN rev1 initially discarded their
72 bytes, changing the final section layout despite a 100% objdiff report.
The same two retention entries are now present in the verified secondary targets.

This leaves an unresolved source-pool representation. Direct references changed
warped-ring code. A typed 120-byte aggregate reproduced warped-ring accesses but
changed seven heavy-fog address/load words; local initializers also differed.
Those reconstructions were not retained. The existing source expressions and
proven constant bytes remain until the original pooling behavior is recovered.

## Validation

Both units pass objdiff and full retail/source-substitution DOL checks in
all four verified versions. The PAL gain is 112 shader data bytes plus 24 cloud
data bytes, completing units with 48 and 15 functions respectively and raising
the PAL completed-unit count from 907 to 909. The changes
preserve section bytes and symbol offsets; only symbol identities change in the
source objects. EN also passes the strict retail checksum, and all four targets
pass `all_source`. The 80 targeted SDA, version-projection, jump-table and pool
audit tests pass.

Naming the PAL save-game getter also adds one exact function and 16 matched code
bytes in engine DLL 23; that larger unit remains incomplete.

```sh
python3 tools/orig/sda_symbol_audit.py GSAP01_rev1 --unit main/shader_dolphin.c --unit dlls/engine/9/9.c
python3 tools/verify_source_link.py GSAP01_rev1 main/shader_dolphin.c dlls/engine/9/9.c
```
