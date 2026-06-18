# Loose DLL cleanup — final status

Byte-exact / match-%-gated cleanup of loose `src/main/dll/*.c` (dead-`FUN_` removal +
unused include/extern pruning + readability), via `tools/dll_cleanup_wave.js`.

## Done
- **~428 loose files cleaned** across all sessions (committed, each match-%-gated).
- Dead-file purge earlier: 71 `.c` + 48 headers removed.
- Second pass complete: the 14 old-pipeline files that still had dead `FUN_` are cleaned.
- 500/529-affected redo backlog: cleared.

## Remaining (NOT swept — other-contributor territory)
24 raw loose files (no header) are **all actively owned by Zachary Canann** (match% work),
most touched within hours/minutes. Left untouched to avoid colliding with live edits
(one owner per `.c`). If picked up later, coordinate with the owner first and run them
through `tools/dll_cleanup_wave.js` (per-file match-gated).

| file | lines | last touched |
|---|---:|---|
| player.c | 18944 | Zachary, mins ago (ACTIVE) |
| dll_0014_unk.c | 5637 | Zachary, hrs |
| dll_0000_baby_snowworm.c | 4973 | Zachary, mins ago (ACTIVE) |
| dll_00C4_tricky.c | 3196 | Zachary, hrs |
| dll_0242_dbstealerworm.c | 3117 | Zachary |
| dll_00E2_staff.c | 2878 | Zachary, 2d |
| dll_00CA_mediumbasket.c | 2531 | Zachary |
| smallbasket.c | 2337 | Zachary, 2d |
| dll_0126_trigger.c | 1974 | Zachary |
| grenade.c | 1901 | Zachary, ~1h (ACTIVE) |
| dll_0017_savegame.c | 1824 | Zachary, mins ago (ACTIVE) |
| dll_80136a40.c | 1665 | Zachary |
| dll_df.c | 1442 | Zachary |
| dll_02C0_front.c | 1253 | Zachary |
| dll_0272_hightop.c | 1218 | Zachary, ~1h (ACTIVE) |
| dll_0271_drakorhoverpad.c | 997 | Zachary |
| dll_00D0_grimble.c | 963 | Zachary |
| drhightop.c | 749 | Zachary |
| dll_0200_dll200.c | 729 | Zachary, 2d |
| dll_00CF_cannonclaw.c | 537 | Zachary |
| dll_0282_barrelgener.c | 505 | Zachary |
| dll_003D_titlemenuitem.c | 451 | Zachary |
| dll_0262_drakormissile.c | 432 | **Jack, 9h** (likely safe) |
| dll_02AD_softbody.c | 123 | Zachary |

Also: `docs/dll_loose_second_pass.md` (historical). Helper scripts + `queue.json` live in
`/tmp/dllclean/` (ephemeral; queue rebuildable from the needs-work heuristic).
