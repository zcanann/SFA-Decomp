# World map: end-game "fly to Dinosaur Planet" → Krazoa Palace redirect

**Status:** blocked on game progress — needs an **end-game save state** (final
sequence, when the world map shows only Great Fox / Dinosaur Planet enabled).

**Question:** At the end of the game the Arwing flight-select screen
(`worldplanet`) has every destination disabled except Great Fox (Dinosaur
Planet), but flying there drops you into **Krazoa Palace**, not the normal
Dinosaur Planet hub. Where is that story-conditional redirect, and what gamebit
gates it?

## What we've already proven (no save needed)

`worldplanet.c` is **100% static** — there is no story branch in the whole file.
Confirming a planet always runs the same path:

- confirm (A): `gWorldPlanetLoadedMapId = loadMapAndParent(gWorldPlanetLoadMapIndices[slot])`
- exit warp: `warpToMap(gWorldPlanetWarpMapIndices[slot], 0)`

Both `gWorldPlanetLoadMapIndices` and `gWorldPlanetWarpMapIndices` are read-only
here and never rewritten elsewhere, so Dinosaur (slot 2) *always* uses
load-map `58` (0x3A) and warp-point `111` (0x6F).

`warpToMap` (`rcp_dolphin.c:884`) only **stages** a warp — it reads a
position/angle from a `.tab` entry via `getTabEntry(p, 28, idx<<4, 16)` and
stores the index in `lbl_803DCEBA`; the pending warp is consumed at
`rcp_dolphin.c:2471` which just sets the player position and calls `mapReload()`.
The actual map came from `loadMapAndParent`, which is also static
(`objprint_dolphin.c:6037`: `sMapFileNameIndexRemapTable` + `sMapFileNameAdjacencyTable`,
no gamebit).

### The key resolution — load maps are the "Arwing flying to X" cutscenes

`loadMapIndices` → `sMapFileNameIndexRemapTable[idx]` (`pi_dolphin.c:8805`) →
file index → name (`sMapFileNameByMapIdTable`, `pi_dolphin.c:8783`):

| slot | planet | loadIdx | remap | file |
|---|---|---|---|---|
| 0 | Walled City | 61 | 59 | `arwingcity` |
| 1 | CloudRunner | 60 | 58 | `arwingcloud` |
| 2 | **Dinosaur** | **58** | **56** | **`arwingtoplanet`** |
| 3 | Dragon Rock | 62 | 60 | `arwingdragon` |
| 4 | DarkIce Mines | 59 | 57 | `arwingdarkice` |

So confirming Dinosaur doesn't load Dinosaur Planet — it loads the
**`arwingtoplanet`** flight cutscene, which then picks the real landing spot.
**That's where the redirect lives.**

## Where it almost certainly is (the last, data-driven hop)

`arwingtoplanet` is data-driven (`arwingtoplanet.romlist.zlb`). At the end of the
flight a **sequence command** issues the warp, executed by the generic
object-sequence code:

- `objseq.c:2443` / `objseq.c:2499` — `warpToMap(*(s16*)(cmd + 2) & 0xfff, 0)`
- `dll_0112_seqobject.c:144` — `warpToMap(mapId, 0)`

The "Hollow vs. Krazoa Palace" choice is therefore a **story-gated conditional
warp baked into that map's sequence data**, not in any `.c`. Note Krazoa Palace
is the **`warlock`** map (map id 15 in `sMapFileNameByMapIdTable`; Warlock
Mountain — see the `GAMEBIT_K1_SPIRIT_DEPOSITED` comment in `gamebits.h`). There
is also a separate `krazoapalace` map file.

## Decisive steps (when an end-game save is available)

1. Boot to the end-game world map (only Dinosaur enabled).
2. `set_breakpoint warpToMap` and `set_breakpoint mapReload` (and optionally the
   two `objseq.c` warp sites at `~0x8028...`).
3. Fly to Dinosaur. On the hit:
   - read `r3` at `warpToMap` = the actual warp index chosen (compare to the
     normal `111`),
   - walk back up `lr` into the objseq/seqobject caller to find the `GameBit_Get`
     that selected it,
   - `read_memory` the map name resolution to confirm `warlock`/`krazoapalace`.
4. Name that gamebit (likely an "all Krazoa spirits collected / final sequence
   armed" flag) and, if it's a clean conditional, document the sequence command.

## Anchors / addresses (retail, GSAE01)

- `warpToMap` `0x800552E8` (`rcp_dolphin.c:884`); pending-warp consume `rcp_dolphin.c:2471`
- `loadMapAndParent` `objprint_dolphin.c:6037`
- tables: `sMapFileNameByMapIdTable` / `sMapFileNameIndexRemapTable` (`pi_dolphin.c:8783/8805`)
- `worldplanet` warp/confirm: `warpToMap` at `worldplanet.c:307`, `loadMapAndParent` at `worldplanet.c:533`
