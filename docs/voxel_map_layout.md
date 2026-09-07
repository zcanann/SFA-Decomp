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
