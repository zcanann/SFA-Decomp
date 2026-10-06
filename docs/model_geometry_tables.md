# Model geometry tables

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

Three consecutive model getters at 0x80028354, 0x80028364, and 0x80028374
index the collision-triangle, collision-group, and display-list arrays with
strides 8, 0x14, and 0x1c. Their header pointers are at +0x5c, +0x60, and
+0xd0 respectively. The header, getters, relocation, and direct callers now
use their canonical record types.

## Shared collision groups

`CollisionPolygonGroup` replaces the map-only `MapTriGroup` name. Models and
maps both consume all six signed-halfword bounds, the first-triangle index,
and the flag word at +0x10, with the same 0x14-byte record stride. Both call
`trackGetPackedSurfaceType`, which extracts flags bits 16 through 23. Map
animation uses the upper flag byte as its separate group selector.

The model walker reads the current first-triangle index at +0 and the end
index at +0x14 (EN 0x80067ea0/0x80067ea4). This is the next group's first
index, matching the map walker's `group[1].firstTri` contract. It is not an
extra field inside the current group, so the type remains 0x14 bytes. The
last range also requires a following boundary halfword; this reconstruction
does not infer the size or contents of any storage beyond that boundary.

The common header is `include/main/collision_polygon.h`. Map accessors and
five existing DLL consumers use that same type, preserving their existing
flags, traversal, and geometry behavior. Model bounds are multiplied by the
caller's scale; map bounds retain their existing coordinate conversions.
The two unknown bytes at +0x0e remain opaque.

`ModelCollisionTriangle` has three unsigned-halfword vertex indices and two
unknown trailing bytes. The model consumer reads exactly the first three
indices. The map triangle's last halfword is a grid-cell mask, but there is
no model-side use establishing that meaning, so it is not imposed here.

## Display lists

`ModelDisplayListEntry` retains its established pointer at +0, length at +4,
and unknown bytes from +6 through +0x1b. The model header now points to this
type and relocation uses `displayLists[i].dlist`. The getter returns the
record directly. No neighboring map display-list layout is substituted.

Primary and shadow lists occupy consecutive groups in the same array.
Relocation processes the sum of their counts; the shadow draw adds the
primary count to its decoded index. The typed getter preserves that caller
contract.

Validation: all 1,002 source objects are byte-identical, including the model,
renderer, both collision consumers, and the five map-animation DLLs. The
full objdiff report is unchanged. All three getters remain 16-byte exact
matches, and `trackBuildModelTriangles` remains 2,632 bytes at 100%. The
strict retail checksum and `all_source` both pass. No runtime behavior or
asset contents were changed.

## Model-relative offsets (2026-10-06)

The 520-byte retail `ObjModel_RelocateModelData` at EN `0x80028F94` reads 21
header words as unsigned byte offsets and replaces them with addresses based
on the model header. `ModelFileHeader` now exposes these two states through
offset/pointer unions. The header's 0xFC-byte target size and every new offset
view are asserted. The relocator takes a `ModelFileHeader*` and uses the named
offsets, removing 43 casted `u32*` reads and the pointer-to-pointer store cast.
The existing unidentified fields at +0x18 and +0x1C retain their unknown roles.

Two subordinate tables undergo the same transition. A `ModelDisplayListEntry`
has a `dlistOffset` view at +0 alongside its runtime `dlist` pointer, retaining
the 0x1C stride. A four-byte `ModelMorphTargetRef` has an `offset` and a
`u16* stream` view. The header's table is now `morphTargets`, and the two
morph-channel selections read each entry's `stream` directly.

The source preserves these observed retail distinctions:

| Site | Relocation condition |
| --- | --- |
| `verticesOffset` | Always add the base, including offset zero |
| Other header offsets | Relocate only nonzero offsets |
| `unk18Offset`, `unk1COffset`, `jointFuzzScalesOffset` | Also require a nonzero `jointDataOffset` |
| Display-list entries | Relocate the sum of primary and shadow counts; entry offset zero still means the model base |
| Morph-table entries | Relocate `morphTargetCount` entries; entry offset zero still means the model base |

The existing call site relocates a newly loaded model before caching it. This
operation is not idempotent. It does not relocate animation allocations or
convert texture IDs; those remain later loader stages. The working Foxhollow
port at `894de8a8edecfad2e455f1a6345e328f50c74aba` expands records in
`modelUnpackFileData` before the separate relocation stage. That native file
decoder supplied a useful comparison of the two stages; retail remains the
evidence for target layout and control flow.

`python3 tools/test_model_relocation.py` runs the production relocator and
record definitions with native pointers above 4 GiB. It checks 732 scenarios
at both `-O0` and `-O2`, with ASan/UBSan and warnings treated as errors. Cases
include isolated offset bits and their complements, mixed optional fields,
absent joints with nonzero dependent offsets, empty tables, shadow-only
display lists, all 510 display lists and all 255 morph entries. Each case
compares the whole allocation against expected pointers and unchanged bytes,
including unrelated header fields, padding, unused table entries and payload.
These fixtures represent already decoded, host-endian native records; they
do not parse retail asset bytes or establish a complete native game loader.
The existing blend-channel test now uses the production morph-reference
union and retains its 22 checked apply passes at each optimization level.

All five verified targets (EN, EN rev1, JP, PAL and PAL rev1) retain a
byte-identical model object: 85 exact functions and 604 exact data bytes.
The shared-header rebuild changes only `dlls/engine/2/2.o` outside that TU:
98 anonymous literal symbols are renumbered, with identical section bytes,
symbol positions and normalized relocations. Its 70 functions remain exact;
all other source object hashes are unchanged. Complete objdiff reports show
no new discrepancies, retaining only the existing `__exception` and
`sal_volume` library accounting exceptions. Full-source builds and strict
source-linked DOL checksums pass for every target. The separate formatting
change preserves every source object hash across all five targets, and both
the active TU and canonical header pass `clang-format --dry-run --Werror`.
