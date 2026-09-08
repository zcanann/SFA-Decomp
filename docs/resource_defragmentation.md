# Resource defragmentation

Target: EN v1.0 (`GSAE01`), common GC/1.3 game compiler.

`defragMemory` walks 88 resource slots with four parallel cursors: a loaded
buffer pointer, a signed-halfword owner ID, a signed 32-bit byte count, and a status
byte. The cursors now use those types and the existing `MldfTables` field
offsets instead of repeated casts and unexplained negative displacements.
The cached base remains in its original address form; the intermediate
0x20000 bias is address arithmetic, not an allocation boundary.

The layout view spans neighbouring globals. `gResourceFileTable` itself is
only 0x160 bytes, and the large merged-table/status storage follows it.
New assertions pin the four cursor bases relative to that symbol:

| Field | Offset | Storage / interpretation |
| --- | --- | --- |
| `loadedFlags` | 0x190e0 | tail of `gObjBlockStatus` |
| `sizes` | 0x19298 | `gResourceFileSizes`, read as signed counts here |
| `ptrs` | 0x195d8 | `gResourceFileBuffers`, interpreted as pointers here |
| `owners` | 0x19738 | `gObjMapBlockInfo`, -1 means no owner |

The eligible switch cases name the A/B animation-curve, voxel-map, TEX0,
block, model, and animation resource IDs. Both passes still clear every
visited status byte, including slots outside that selection.

A nonzero mode first moves eligible region-0 buffers while allocations are
restricted to regions 1 and 2. Mode 2 retains the existing texture exclusions.
The main loop makes at most ten passes and stops when no relocation succeeds.
It favors lower addresses for large region-0 resources and higher addresses
for smaller ones. After the first pass, modes other than 2 may also bring
allocations of at least 0x3000 bytes back from regions 1/2 into region 0.

`MM_REGION0_LARGE_ALLOCATION_THRESHOLD` is shared with the allocator. Its
0x33450 cutoff separates region 0's forward first-fit allocation path from
its reverse best-fit small-allocation path; the small-allocation split also
uses that cutoff. Defragmentation compares the resource payload size, whereas
the allocator compares the rounded allocation request. The extra 0x20 bytes
requested by defragmentation and that boundary distinction are preserved.
All four active source uses now share the definition in `main/mm.h`.

Allocation failures, immediate-free delay restoration, mode-specific exits,
and the initial texture-allocation-state writes are unchanged. In particular,
the early returns still occur before the final allocation-state reset.

Validation: all 1,002 source objects remain byte-identical after both the
recovery and formatting. `defragMemory` remains 1,028 bytes at 99.76654%,
with eleven operand differences exchanging the first pass's file-index and
replacement-buffer registers. This is structure and naming recovery, not an
increase in exact-function count. Full source compilation and the strict
retail checksum build pass. The separate formatting change preserves every
non-brace token and every generated object; it attaches existing braces and
adds braces around previously unbraced control-flow bodies.
