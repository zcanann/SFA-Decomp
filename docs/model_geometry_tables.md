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
The +0x18 and +0x1C tables were subsequently recovered as collision radii and
length scales; see [object_matching.md](object_matching.md#skeleton-collision-bound-initialization-2026-10-06).

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
| `jointCollisionRadiiOffset`, `jointCollisionLengthScalesOffset`, `jointFuzzScalesOffset` | Also require a nonzero `jointDataOffset` |
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

## Model texture references (2026-10-06)

The table at header +0x20 is now `textureEntries`, with four-byte target
`ModelTextureEntry` records. Each record starts as a signed asset ID. The
loader replaces it with the opaque result of `textureLoad(-(assetId | 0x8000),
1)`, and shader resolution copies its runtime reference into the relevant
shader slots. The union exposes `assetId`, `loadResult`, and `reference`
without claiming that every loaded value is a texture pointer. The runtime
view now uses the pointer-width `TextureReference` defined in `main/texture.h`;
serialized asset IDs and shader indices keep their signed 32-bit views.

`textureLoad` establishes the distinction: a cached handle is one-based, but
the uncompressed texture path returns a direct address even when a handle was
requested. `textureIdxToPtr` recognizes direct target addresses by bit 31 and
otherwise looks up the handle minus one. Its mask also retains any higher
native address bits, so a pointer above 4 GiB is not mistaken for a handle
when its low word has bit 31 clear. The model getter, release path and modgfx
DLL 91 consumer retain that decoder. Target layout assertions pin all three
views to the same four-byte word.

Shader layer, auxiliary, indirect and +0x18 slots expose separate runtime
reference views. Model resolution writes the complete runtime value, including
a full-width zero for absent +0x18 textures. Model renderers read those views
instead of aliasing the first word as `int*` or reading the serialized index.
The bump-stage helper carries the same reference type; the object renderer's
resolved-texture cache now holds `Texture*` rather than truncating the address.

The loader and shader resolver now use the canonical header and shader fields,
removing raw header offsets and integer-held table addresses. Shader indices
retain the signed `-1` sentinel; `unk1C` retains its separate `-1`/`-2` to zero,
otherwise one conversion. Foxhollow's working native implementation at
`894de8a8edecfad2e455f1a6345e328f50c74aba` informed the table and pointer-width
review. The +0x18 field retains its complete reference and decoder call; the
native port's boolean reduction is not adopted. This change does not establish
a complete native texture port or deserialize pointer-bearing retail records
into the wider native layouts.

`python3 tools/test_model_texture_references.py` executes the production
relocator, loader, shader resolver, getter, layer accessor and texture decoder,
with canonical texture, registry, shader and model record declarations. It
checks all 701 registry sizes, 945 shader cases and 20 load paths at both `-O0`
and `-O2` with ASan/UBSan. Cases cover every valid handle, invalid bounds,
retail address bit patterns, mixed handle/address/null values, signed
sentinels, flag masks, cache hits, mapped/direct model IDs and texture counts
through 255. Two actual texture allocations straddle a 4 GiB boundary and
have opposite bit-31 values. Handle resolution also follows replacement of a
registry entry. IO and animation services remain spies.

Six scratch negative controls reject a narrowed decoder argument, the old
bit-31-only mask, narrowed model/layer storage, a partial-width null store and
an off-by-one registry bound. The complete 19-test model suite passes,
including the existing 732-case relocation probe. Its matrix fixture now
includes the production helper already called by the matrix initializer.

All five configured versions pass `all_source`, strict retail DOL checksums
and the complete active objdiff inventory audit. Every affected TU remains
100% exact. Source objects are unchanged except for anonymous literal-symbol
renumbering in engine DLL 2 and `objprint_dolphin`; section contents, flags,
alignment, symbol positions and relocation targets remain identical. The two
existing SDK/MusyX report-accounting exceptions are unchanged.

The loader's four existing one-element locals remain a source-shape limitation.
A scalar rewrite with the same byte-offset loop changes one instruction at
`ObjModel_Load+0x7C` from `mr r28,r30` to `li r28,0`; indexed rewrites also change
register allocation. They were not retained. This recovery improves the table
contract and field accesses without claiming the remaining locals are original.

All source object bytes remain unchanged across EN, EN rev1, JP, PAL and PAL
rev1, including the complete model TU and the shared-header consumers. Full
objdiff reports retain only the two previously documented library accounting
exceptions; there are no new discrepancies. All five `all_source` builds and
strict source-linked retail DOL checks pass. The separate formatting change
also preserves every source object byte.
