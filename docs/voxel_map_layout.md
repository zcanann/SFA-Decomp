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

## Cache storage ownership

The subsequent ownership pass defines `VoxMaps gVoxMaps` in `voxmaps.c`, replacing
the overlapping external aliases described above. EN references to the cache,
timer base, and route-state base all come from this TU. The BSS span starts at
0x803387a0, immediately after `curves.c`; `modelEngine.c` follows at 0x80338818.
The same TU order occurs in text, data, and small BSS.

| Cache offset | Storage | Size |
| --- | --- | --- |
| 0x00 | Six slot grid-origin pairs | 0x18 |
| 0x18 | Six slot ages | 0x18 |
| 0x30 | Six block IDs | 0x18 |
| 0x48 | Active block world origin | 0x08 |
| 0x50 | Active block grid origin | 0x08 |
| 0x58 | Active map pointer | 0x04 |
| 0x5c | Six loaded-map buffer pointers | 0x18 |

The existing cache view covers 0x74 bytes. `VoxState` is now its actual embedded
0x14-byte member at +0x48, and timers are selected through the six-element array.
The original declaration spelling is unknown; the aggregate models the evidenced
contiguous accesses without conflicting definitions at interior addresses.
The four bytes before the next TU are left to natural eight-byte section
alignment, rather than added as an unsupported field. The compiler emits one
116-byte BSS symbol with eight-byte section alignment, and objdiff matches the
complete 604-byte data allocation for this unit.

Under GC/1.3, selecting the embedded members changes four functions' address
formation. For example, `voxmaps_updateTimers` starts from the cache base and
uses a +0x18 first access, whereas retail starts from the timer address and uses
a zero displacement. The following accesses reach the same six elements.
`voxmaps_visitRouteNeighbor`, `voxmaps_traceTraversableRoute`, and
`voxmaps_traceLine` similarly fold route-state offsets into loads. Across these
four functions, 24 instruction bytes change, with no size changes. The unit
score moves from 99.53371% to 99.524765%, and exact functions from 25/28 to 22/28.
This tradeoff removes unresolved, overlapping storage aliases. Other existing
allocated sections and named symbol positions are unchanged, and all 1,001
other source objects remain byte-identical.

The strict retail checksum and `ninja all_source` pass. These checks establish
buildability and layout, not runtime coverage of the walkers. The retail NULL
stores to the active map and the traversable-route X step's use of the Z origin
are preserved.

## Native cache arrays and deferred emission (2026-09-07)

The aggregate above was a provisional ownership view. It is now replaced by
five ordinary definitions: `gVoxMapsSlotOrigins[6]`, `gVoxMapsSlotAges[6]`,
`gVoxMapsBlockIds[6]`, `gVoxMapsActiveState`, and `gVoxMapsBuffers[6]`.
Their offsets and sizes are exactly the table above, with the active state's
three fields retaining their established `VoxState` layout. No external aliases,
manual shared-base pointer, padding objects, or section directives are needed.
The total BSS extent remains 0x74 bytes plus four bytes of link alignment.

EN's timer and route walkers address the age array and active state directly,
while initialization and cache replacement use a common base spanning the
arrays. This combination, together with initialization following its consumers
in retail text, supports deferred emission of ordinary definitions in reverse
source order. It is evidence for this reconstruction, not proof of a historical
build command. The existing GC/1.3 compiler, optimization settings, automatic
inlining, and TU boundaries remain; only deferred emission is added. The compiler
creates its own shared BSS base and preserves all five physical offsets.
Without deferred emission, definitions before the functions allocate arrays in
first-reference order; definitions after them preserve layout but lose the
shared base. Neither intermediate form is retained.

The reset routine now indexes the five native arrays directly, removing all
five one-element pointer arrays and their staged initialization. Its complete
156-byte function is unchanged. Initialization likewise uses indexed native
arrays and remains exact. The oldest-slot loop uses its signed integer index
directly; the previous unsigned copy caused five unnecessary address additions
with native storage. Existing age sentinels, six-slot capacity, signed block
IDs, and the retail NULL assignments to the active map remain unchanged.

Three functions become exact: `voxmaps_updateTimers` (160 bytes),
`voxmaps_traceLine` (1,060 bytes), and `voxmaps_traceTraversableRoute`
(1,204 bytes). All 22 previously exact functions remain exact. The unit improves
from 99.524765% to 99.665924%, with 25/28 exact functions and 2,424 additional
matched code bytes. All 604 data bytes remain exact. The three remaining
functions have the retail instruction counts; their residuals are register
allocation differences. The unit remains `NonMatching`.

Validation: `ninja all_source` and the strict matching checksum both pass with
30-second timeouts. The generated DOL is byte-identical to retail. All allocated
non-text sections retain their bytes, extents, and alignment; every pre-existing
non-text symbol outside the replaced aggregate retains its exact layout. The
five new BSS symbol offsets are audited independently of objdiff. The matching
link still uses the retail object for this incomplete unit, so its checksum does
not establish runtime coverage of the reconstructed cache-loader code.

The TU and canonical header pass `clang-format --dry-run --Werror`.
Running the formatter produces no source diff and preserves the complete object,
so no separate formatting commit is required.

## Shared route-queue operations (2026-09-07)

Four insertion sequences now call the private inline `voxmaps_queueNode` helper.
It stores a 16-bit node index and priority after incrementing the signed queue
count, then invokes the existing sift-up operation. The caller still inverts
the accumulated route cost for ordinary insertions and supplies 0xfffe for the
goal-node insertion. These argument lifetimes reproduce the retail register
choices in `voxmaps_updateRoutePath`, making all 1,192 bytes exact.

The existing-node update is extracted as `voxmaps_reprioritizeNode`; its upward
case shares `heapSiftUp` instead of duplicating it. The helper retains the
inclusive search from slot zero through the queue count, the original found-slot
lifetime, and the conditional downward/upward sift. The caller still supplies
the un-inverted cost here, unlike ordinary insertion. This pass records that
retail distinction without silently changing the search algorithm.

The unit advances from 25/28 to 26/28 exact functions and from 99.665924% to
99.870766%. Neighbor expansion improves from 98.98955% to 99.651566%; its
2,296-byte instruction count is unchanged. Only these two functions change
instruction bytes. All named symbol layouts and allocated non-text section
bytes, sizes, and alignments are unchanged. The current GC/1.3 compiler profile
and TU structure are unchanged. The remaining two functions differ only in
register allocation, and the unit remains `NonMatching`.

Both `ninja all_source` and the strict matching checksum pass with 30-second
limits. The linked DOL remains byte-identical to retail; as above, the unit's
`NonMatching` status means that check uses its retail object. Objdiff confirms
that no other unit's match measures change.
