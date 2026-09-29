# LinkI runtime restoration (EN v1.0)

LinkI (map 74, `linki`) retains an 8 by 7 MAPS grid with six occupied cells
and 32 romlist placements, but has no GLOBALMA placement. The practice build
registers its unused RAM slot after `initMaps`, using the retail
`mapInitSetRects` helper. No disc map assets are changed.

The practice origin is grid (60, 60), layer 0, deliberately separate from
retail areas. The generator checks that its bounds overlap no retail map on
that layer. This is an experimental location, not a recovered original world
position. Both runtime registration and menu coordinates use the generated
`PRACTICE_LINKI_ORIGIN` constant.

Unused > LinkI > Entrance uses the retained setup point's X/Z, with Y lifted
50 units above its placement. CloudRunner Fortress (map 12, directory 18) is
loaded as the auxiliary bank: LinkI alone gives Fox a fallback colored model.
The existing arrival-group policy enables LinkI group 0.

In isolated Dolphin tests, the entrance rendered a textured stone/metal
interior and barred doorway. With the auxiliary bank, Fox rendered normally.
Raising Fox from Y 1178.06006 to 1328.06006 with movement cheats disabled made
him fall through intermediate heights and settle back at 1178.06006 for more
than 100 frames. This establishes visible scenery and floor collision at the
entrance, not every block or the old event sequence.

The isolated placement does not reconnect the corridor to CloudRunner
Fortress or its race. Surviving exit triggers, cutscenes, conveyors, actors and
save/respawn behavior are not fully validated; use the practice warp menu to
leave. This stays in Unused, rather than the normal dungeon progression.

The compiled-PPC regression executes the retail bounds/cell initialization
helper against an audited EN fixture, checks the six occupied cells, and
verifies all other map slots and adjacency entries remain unchanged. The
practice payload remains inside its existing 64 KiB reservation. Disabled
practice builds still define no code and preserve the retail DOL.

Local captures and the gravity trace: `build/practice/linki-bank-check/`.
The final-build recheck is recorded in `build/practice/linki-final-check/`.
