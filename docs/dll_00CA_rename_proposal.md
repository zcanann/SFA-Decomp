# `dll_00CA_mediumbasket` → `dll_00CA_icebaddie` (cut content) — APPLIED

**Status:** APPLIED. The file was renamed to `dll_00CA_icebaddie.c/.h` and all
`mediumbasket_*` / `dll_CA_*` symbols, the `gMediumBasketStateHandlersA/B`
tables, the `dll_CA` descriptor object (→ `gIceBaddieObjDescriptor`) and the
`MediumbasketControl` struct were renamed to the `iceBaddie`/`IceBaddie`
namespace across `.c` / `.h` / `symbols.txt` / `splits.txt` / `configure.py` /
`dll_00CE_dllce.c` / `dll_00C9_enemy.c` / `scarab.h`. The rename plus the
earlier behavioral renames are match-%-neutral (`.text` byte-identical to the
pristine pre-rename build). The optional slot-handler behavioral names below are
*not* applied — left for a future pass.

`iceBaddie` is a descriptive placeholder: this is cut content with no retail
name (see below).

## Why the current name is wrong

`dll_00CA_mediumbasket` is a placeholder guessed from the DLL's numeric id by a
prior agent. Investigation (static + retail-data) shows it is **cut/unused
content** with **no retail name**:

- No `OBJECTS.bin` definition references dll-id `0xCA` → the object has no name
  and cannot be spawned through the normal romlist/object path.
- It appears in **zero** map romlists (all ~115 scanned) → never placed.
- **Nothing** in the entire game reads `gResourceDescriptors[0xCA]` or spawns
  dll-id 202 — the only references to the descriptor / `dll_CA_*` functions are
  the descriptor table entry and the struct itself. (`dll_CA_update` does read
  `placementData`, i.e. it was *designed* to be placed; the placements were
  removed before release.)

## What it actually is

A fully-implemented **cut ice baddie in the ChukChuk family**:
- A `GroundBaddie` (extra size `0x458` = `GroundBaddieState`) that pursues the
  player (aggression / aggroRange, hit points) and dies.
- **Spits the retail `IceBall` projectile** (object id 100 → def "IceBall";
  see `mediumbasket_spawnIceBall`) — the same projectile family as its
  descriptor-table neighbours ChukChuk (`0xCC`) and IceBall (`0xCD`), whose
  descriptor structs this TU also hosts.
- State machine: drop / land (camera-shake stomp), spin, open, hide-reset,
  impact / contact-hit, height-blend, plus an A/B target-engagement dispatch via
  `gMediumBasketStateHandlersA/B` (filled by `fn_8015DAE8` in dll_CE).
- The `*WhirlpoolGroup` / `initWhirlpoolState` helpers in this TU are **shared**
  engine utilities (the generic enemy DLL `dll_00C9` calls them) — not specific
  to this creature; keep them general when renaming.

## Proposed names

There is no canonical retail name, so this is a descriptive choice. Suggested
prefix **`iceBaddie`** / file **`dll_00CA_icebaddie.c`** (alternatives:
`icechukbaddie`, `frostbaddie`). To apply:

1. `src/main/dll/dll_00CA_mediumbasket.c` → `dll_00CA_icebaddie.c`
   (+ `include/main/dll/dll_00CA_mediumbasket.h`).
2. Update `configure.py` and `config/GSAE01/splits.txt` for the new path.
3. Symbol-prefix renames in source **and** `config/GSAE01/symbols.txt`:
   - `mediumbasket_*` → `iceBaddie_*`
   - `dll_CA_*` → `iceBaddie_*` (descriptor callbacks)
   - `gMediumBasketStateHandlersA/B` → `gIceBaddieStateHandlersA/B`
     (also referenced in `dll_00CE_dllce.c`).
4. Update `#include "main/dll/dll_00CA_mediumbasket.h"` in `dll_00C9_enemy.c`.

## Optional: behavioral names for the slot-numbered state handlers

These are currently named by their dispatch-table slot (a legitimate scheme).
If a behavioral pass is wanted, proposed names (verify against asm before
applying — this creature is cut, so no live confirmation is possible):

| current | proposed | role |
|---|---|---|
| `stateHandlerA05` | `updateRandomChargeState` | picks attack move 6/10, charge toward target |
| `stateHandlerA06` | `updateRandomLungeState` | picks attack move 7/3, lunge toward target |
| `stateHandlerA0B` | `updateAdvanceState` | targetState 2/3, move 2, advance |
| `stateHandlerB01` | `transitionFromHurt` | hp<1 → die; controlMode 12 → re-engage |
| `stateHandlerB02` | `transitionToDespawn` | disable hits, free object on moveDone |
| `stateHandlerB03` | `transitionResetGameBits` | clears spawn gamebit, sets alive gamebit |
| `stateHandlerB04` | `transitionReengage` | re-dispatch player interface on moveJustStartedB |
| `stateHandlerB05` | `transitionFromSpin` | controlMode 3 → idle, else return 8 |
| `stateHandlerB06` | `updateRouteToTarget` | builds route to target, picks attack |
| `stateHandlerB07` | `dispatchAttackPattern` | cycles `attackPatternIndex` through attack tables |

(Names above are derived from code behavior only.)
