# Dragon Rock fire-crawler life-force door (3 crawlers, door wants 2)

**Status:** blocked — needs a save state in **Dragon Rock** (the final dungeon).
We're still at the very start of the game, so this can't be run yet.

## The question
In Dragon Rock there's a life-force door (a `SpiritDoorLock`, DLL 0x167) that
unlocks after killing **fire crawlers**. There are **3 fire crawlers nearby,
but the door only requires 2 kills.** So:

1. Do **all 3** crawlers count toward this door (i.e. they share one
   `deathGamebit` / counter and the door opens at count == 2, so *any* 2 of
   the 3 work)?
2. Or do **specific** crawlers have **different `deathGamebit`s** — i.e. only
   2 of the 3 are wired to this door, and the 3rd is unrelated (a decoy /
   belongs to something else)?

## Why this is interesting
It tests the multi-kill / shared-counter hypothesis we formed at the start of
the game (Krazoa Shrine life-force seal). If `gameBitIncrement` on a shared
`deathGamebit` is how "kill N of a group" is expressed, Dragon Rock's
3-crawlers-need-2 is the clean test case.

## Background mechanic (already mapped, start of game — Krazoa Shrine)
Confirmed live there:
- **`SpiritDoorLock` (0x167)** = the red life-force seal; orbits the
  **`SpiritDoorSpirit` (0x157)** "skulls" in object group `0x4E`. When the
  ring empties (`orbitCount == 0`) it sets `placement->doneGameBit` -> gate opens.
- Each skull-spirit watches `placement->gateGameBit`; when that bit is set the
  skull leaves the ring.
- An enemy's defeat runs **`tricky_handleDefeat`** (dll_00C4_tricky.c), which,
  unless the baddie is sequence-driven (`controlFlags & 0x40000000`), does
  `gameBitIncrement(placement+0x18 = deathGamebit)` and
  `GameBit_Set(placement+0x1a = clearOnDeathGamebit, 0)`.
- The link "kill monster -> skull vanishes" is purely level data: the enemy's
  `deathGamebit` == the skull-spirit's `gateGameBit` (same id).
- (Krazoa Shrine instance was a single bit `0xECB`; it ALSO gated the enemy's
  respawn — clearing it respawned the monster and re-showed the skull.)

## How to run it (when in Dragon Rock, at the door with the 3 crawlers)
1. **Read each crawler's `deathGamebit`** (placement `+0x18`): find the 3
   fire-crawler objects (descriptor chain / object-group census), read
   `obj->anim.placementData` (`obj+0x4C`) then `placement+0x18` (s16). Compare
   the 3 values:
   - All three equal -> shared counter (any 2 of 3).
   - Two equal + one different -> the odd one is a decoy / wired elsewhere.
2. **Read the door's spirits**: census the SpiritDoorSpirit objects in group
   `0x4E` near the door; read each `placement->gateGameBit` (spirit placement
   `+0x1E`). See how many skulls and which bit(s) they watch.
3. **Confirm the threshold**: is it `gameBitIncrement` on one shared bit checked
   for value >= 2, or 2 separate per-crawler bits? Inspect the door's
   `activeGameBit`/`doneGameBit` and whatever evaluates the count.
4. **Live confirm (snapshot-diff / watchpoint)** like we did for `0xECB`:
   snapshot game-bit regions, kill a crawler, diff to see which bit/counter
   moved; `trace_breakpoint`/watch the storage byte to catch the
   `tricky_handleDefeat -> gameBitIncrement` for each crawler and read the id.

## Expected artifacts to produce
- The 3 crawlers' `deathGamebit` ids (and whether they match).
- The door's `gateGameBit`(s) / threshold.
- A note on whether killing the "wrong" crawler counts.
