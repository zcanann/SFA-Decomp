# Voxel-map records and cache views

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

`voxmaps_getRouteNode` ranks set bits in the occupancy bitmap and scales the
result by four to find a node. Its callers read individual bytes, then extract
two-bit cells using an X-dependent shift. `VoxMapNode` therefore describes four
packed row bytes, replacing the previous `int` element type without changing
its stride. The loader still relocates the serialized node offset in place.
The earlier retail-corpus findings are recorded in `docs/wiki/Maps.md`, under
“VOXMAP — decoded, and its consumer link is severed in retail.”

The six cache slots share one capacity constant between the record definitions
and the initialization, replacement, timer, and reset loops. An unused slot has
block ID -2 and age 0x40000000. Used-slot ages stop at 0x3fffffff, so an unused
slot ranks above every used slot during the oldest-slot search. The constants
retain the original signed integer types.

The reset routine previously derived buffer, block-ID, and timer pointers by
advancing a `VoxMapSlotOrigin*` by 23, 12, and 6 elements, beyond the six-element
origin array. It now converts the initial first-member pointer back to the
existing `VoxMaps` view and selects the actual fields. Header assertions cover
the field offsets and complete view size. This does not establish new global
ownership or change the existing overlapping `VoxState` view.

The reset function's one-element pointer locals remain. Converting all five to
scalars adds an instruction (156 to 160 bytes); converting each individually
also changes the object. Canonical field access and a `VoxMapFile**` buffer
cursor preserve the existing code without those out-of-range array offsets.

Validation: all 1,002 compiled source object hashes are unchanged, as is the
complete objdiff report. The voxel-map unit remains 99.53371% with 25 of 28
functions exact; reset remains 156 bytes and exact. The strict retail DOL
checksum and `ninja all_source` both pass. The retail NULL stores to `activeMap` remain:
the packed records describe the loaded assets, but the retail route walkers
still do not receive those loaded maps.

## Route search API

The queue processor passes a `RouteNode` directly to neighbor expansion. Retail
loads its accumulated cost from +0x08 and its coordinates from +0x00/+0x02/+0x04.
The removed `VoxBoxArg` overlay described this same prefix but mislabeled the
heuristic cost at +0x06 as padding. Both neighbor functions now accept the
canonical node; the unused parent-pointer parameter in the visitor remains in
the ABI.

`RouteNode.expanded` is cleared when a search starts and set immediately before
expanding a popped, non-goal node. An existing node can have its cost and parent
updated only while this byte is zero. `RouteState.currentNodeIndex` records the
last popped node and seeds waypoint reconstruction. These are the meanings
previously hidden behind `flag` and `cur`.

The ground-baddie callers in object slots 202 and 203 establish the navigation
record's position roles:

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | `startPos` | Filled from the moving object's position; initializes the search start. |
| 0x0c | `goalPos` | Filled from the target object's position; initializes the search goal. |
| 0x18 | `waypointPos` | Output consumed by `moveTowardPoint`. |
| 0x24 | `searchIteration` | Zero starts a search; pending updates increment it. |
| 0x25 | `useDirectSteering` | Selects direct/fallback movement rather than a reconstructed intermediate waypoint. |
| 0x26 | `maxSearchIterations` | Compared against the pending-search iteration before returning a partial route. |
| 0x27 | `nodesPerUpdate` | Passed as the queue-processing budget. |

The previous `destPos`/`curPos` names reversed the apparent input roles. A direct
trace copies the goal to the output; exhausted search copies the start instead.
Both paths set `useDirectSteering`, so that flag must not be interpreted as
“goal reached” or “route found.” Engine slot 25 initializes the iteration limit
to four and the per-update node budget to twenty, and also consumes the movement
flag. All three consumers use the same canonical names.
