# Arwing flight: the cut `0x6d8`-`0x6db` pickups (confirmed cut, code-verified)

**Status:** deferred, not blocked - the code path is fully understood and
live-verified. What remains needs either **asset extraction** (their models/
textures) or reaching the **locked planet Arwing flights** to see whether any
place them.

**Question:** `arwbombcoll` (dll_0x29F) dispatches four in-flight pickup types by
`seqId` - `0x6d8`/`0x6d9`/`0x6da`/`0x6db` - each of which only bumps a per-Arwing
counter. What are they, and do they appear anywhere?

## The full Arwing-flight pickup dispatch (mapped)

Two object systems feed the Arwing's rewards:

**A. `ring` objects (dll_0x2A0), via `arwbombcoll_handleArwingHit` - by `state->mode`:**
| mode | reward |
|---|---|
| 0 | health +1, score +10 (the "silver ring" - live-confirmed to give health) |
| 1 | maxHealth +1, full heal |
| 3 / 4 | `gameBitIncrement(placement.eventId)` (event pickup) |
| else (2, ...) | **gold ring**: `incrementCollectedRingCount` + health +1, score +20; feeds the arwlevelcon ring gate |

**B. `arwbombcoll` objects (dll_0x29F), via `arwbombcoll_update` - `switch(obj->seqId)`:**
| seqId | reward |
|---|---|
| `0x608` | bomb (`arwarwing_addBomb`) |
| `0x609` | laser upgrade (`arwarwing_upgradeLaserLevel`) |
| `0x60a` | **nothing** (`case 0x60a: break;`) - a separate no-op, identity unknown |
| `0x6d8` | `arwarwing_incrementPickup6D8Count` + SFX `eba_leavesopen` |
| `0x6d9` | `arwarwing_incrementPickup6D9Count` + same SFX |
| `0x6da` | `arwarwing_incrementPickup6DACount` + same SFX |
| `0x6db` | `arwarwing_incrementPickup6DBCount` + same SFX |

## Why they look cut

- The four counters are `ArwingState.pickup6D8Count..pickup6DBCount` (u8, offsets
  0x472-0x475). They are **incremented but never read** anywhere in the code -
  no getter, no results screen, no bonus. Purely write-only.
- All four behave **identically** (same SFX, just a counter) - they differ only
  visually, so only assets/level-placement could distinguish them.
- They do **not** appear in the reachable intro Dinosaur flight (`arwingtoplanet`)
  - all four counts stayed 0 and none of the four breakpoints fired in normal play.
- Per the player's recollection the final Andross Arwing fight has only silver
  rings and bombs - so they are likely not there either.

## Live repro (verified)

Morph any live `arwbombcoll` pickup into a cut one and fly through it:
1. `set_breakpoint arwbombcoll_update`, `continue` until r3 is a pickup with a
   convenient `seqId` (bomb `0x608` at obj+0x46), reading obj+0x46.
2. `write_memory obj+0x46 = 0x06d8` (optionally snap obj+0x0C localPos onto the
   Arwing at `*gArwing`+0x0C so you can't miss it).
3. `set_breakpoint arwarwing_incrementPickup6D8Count`, resume, fly through.

Result (done 2026): the breakpoint fired (`lr = arwbombcoll_update+0x3b0`,
r3 = the Arwing), so the cut path is **fully wired and functional**. The model
stayed the bomb's (arwbombcoll loads its model at spawn and does not re-pick it
from `seqId`), so the cut texture is not visible this way - a faint green-flame
effect was reported but unconfirmed.

## To close it out
- Extract the model/texture for object types `0x6d8`-`0x6db` (and `0x60a`) from
  the arwing map assets to learn what they are.
- When the locked planet Arwing flights (`arwingcloud`/`arwingcity`/`arwingdragon`/
  `arwingdarkice`) are reachable, breakpoint the four increments during those to
  see if any level actually places them.

## Anchors (retail, GSAE01)
- `arwbombcoll_update` `0x8022F5C4`, seqId switch ~`+0x3b0`; `arwbombcoll_handleArwingHit` `0x8022FB5C`
- `arwarwing_incrementPickup6D8Count` `0x8022D5DC` (6D9 `0x8022D5C8`, 6DA `0x8022D5A0`, 6DB `0x8022D5B4`)
- `ArwingState.pickup6D8Count` at extra+0x472; `gArwing` `0x803DDD88`
- dispatch source: `src/main/dll/ARW/dll_029F_arwbombcoll.c`
