# Future investigations

Parking lot for investigations that can't be done yet (e.g. they need a
later point in the game than the current save state reaches), or that are
deferred for later. Each file is one self-contained investigation: the
question, why it's blocked, and the concrete steps / tooling to run when
it becomes reachable.

| file | needs | one-line question |
|---|---|---|
| `dragon_rock_firecrawler_lifeforce_door.md` | reach Dragon Rock (final dungeon) | do all 3 nearby fire crawlers count for the 2-kill life-force door, or do specific ones have different `deathGamebit`s? |
| `sfx_trigger_computed_ids.md` | table dumps / live debugger | 20 SFX call sites whose trigger id is computed (table/field/level-data) — name the source tables, confirm the rest live |
| `worldmap_dinosaur_krazoa_redirect.md` | end-game save state | end-game "fly to Dinosaur Planet" lands in Krazoa Palace — redirect is in the `arwingtoplanet` flight sequence (data-driven), which gamebit gates it? |
| `arwing_cut_pickups_6d8_6db.md` | asset extraction / locked planet flights | four Arwing pickups (`seqId 0x6d8-0x6db`) are code-complete but unplaced (write-only counters) — confirmed cut live; what are they? |
