# Model animation loading

`modelLoadAnimations` at EN v1.0 `80025420` now uses the canonical
`ModelFileHeader` and signed animation-ID arrays. The first group base is
written through `animGroupBaseIndices`; each `-1` ID establishes the next
group's base at the following index. This removes the raw `+0x70` store and
the one-element byte-offset array without changing the retail loop.

The loader has two distinct resource paths:

- With `MODEL_FLAG_CACHED_ANIMATIONS`, the caller's buffer retains the
  `MODANIM.BIN` ID list, padded to eight bytes. Animations are subsequently
  fetched through the move-cache path. `moveData` is cleared.
- Otherwise, the ID list temporarily uses `gModelResourceBuffer`. The caller's
  buffer holds an animation-pointer table followed by eight-byte-aligned
  `AMAP.BIN` data. Each non-sentinel ID acquires an animation cache reference;
  a failed acquisition releases earlier references and returns 1. Successful
  setup returns 0.

`gModelAnimOffsetTable` is reused as I/O scratch: the first `MODANIM.TAB`
lookup reads a signed halfword, while the later `AMAP.TAB` lookup reads words
and derives a byte span from adjacent offsets. The first view uses the signed
halfword array in `ModelAnimationOffsetScratch`. A mutable local starts with the resource ID
and is later reused for the AMAP byte span; the buffer cursor is a `u8*`
parameter. Separating the ID and byte span into independent locals changes
register allocation. Cache locals are named for animations rather than
texture atlases.

The existing overflow diagnostic, group-table writes, reference-count
signedness, and error cleanup are preserved. The change adds no new bounds
checks or allocation behavior. The zero-animation case still performs its
initial table read before returning.

The loader now matches all 944 bytes under GC/1.3, raising the EN model TU
from 78/85 to 79/85 exact functions. The previous 99.66102% body exchanged
`r27` and `r31`: it kept the ID/span in the parameter and copied the buffer
parameter into a local. Keeping the cursor as the parameter and the mutable
ID/span as a local recovers retail allocation without changing the algorithm.
The public declaration now expresses the buffer's byte-pointer type.

LLDB captures of the ordinary GC/1.3 compiler verified all 236 instructions
and replayed register simplification and physical coloring. Instrumented and
ordinary compiles produced identical objects for each source version. The
matched capture has zero retail instruction differences. This establishes
code generation, not the original source spelling.

All other 84 function bodies, symbol layouts, relocations, and allocated data
remain unchanged. `clang-format` makes no additional edits and the rebuilt
object is byte-identical to the pre-format result. The strict EN retail
checksum and `all_source` builds pass. The TU remains `NonMatching` because
other functions and data are still incomplete.

The same source also scores 100% for this function in EN rev1, JP, and PAL
rev1 after verifying each input DOL against its configured SHA-1. These are
per-function objdiff checks, not complete regional source-link claims. The
existing matrix-preparation test still passes 144 scenarios each at `-O0`
and `-O2`.

## Shared move-resource ownership

`ModelFileHeader.moveData` now points directly to an array of
`ObjAnimMoveData*`. The former byte-pointer alias `animationModelPtrs` is
removed. Loading, playback, root-curve sampling, and release all use the same
field; byte casts remain where a consumer walks the packed frame stream or
uses the release loop's existing byte offset.

The first byte of `ObjAnimMoveData` is a runtime `refCount`, not padding.
`modelLoadAnimations`, `loadAnimation`, and the initial-move loading macro
set it to 1 after decompression and increment it on a shared-cache hit.
Load-failure cleanup and `ObjModel_Release` decrement that same byte and
remove/free the cache entry when the narrowed result is nonpositive as an
`s8`. Storage remains `u8`, preserving both wraparound and the signed release
test. The field is unused for private `ObjAnimCachedMove` resources, which
are loaded directly into their owner's buffer and do not acquire these
shared-cache references. Its new offset assertion pins it to byte zero;
the six-byte prefix and all following fields retain their existing layout.

The initial-move macro is named `MODEL_LOAD_INITIAL_MOVE` instead of the
misleading `LOADCOLOR_BLOCK`. It reads the canonical animation-ID array and
model ID fields. Cache pointers and loader locals identify animation
resources, sizes, file offsets, and cache slots; the existing scratch aliases
and parameter reuse remain where they preserve generated code.

All 1,002 source objects remain byte-identical after both the recovery and
formatting. This includes every model and animation function, their data,
symbol layouts, and relocations; match scores are unchanged. `ninja all_source`
and the strict retail checksum build both pass. Formatting the active model
source and canonical headers passes the dry-run check; only the model source
needs a separate formatting diff.

## Shared resource scratch allocation

`ModelResourceScratch` now describes the initializer's single `0x830`-byte
allocation. The first `0x800` bytes are signed halfword ID scratch, used for
`MODELIND.bin` indirection and the temporary `MODANIM.BIN` list. The final
`0x30` bytes are shared offset scratch with explicit union views:

| Allocation offset | View | Retail access |
| --- | --- | --- |
| `0x000` | `ids[0x400]` | Eight-byte model-indirection reads and variable-length animation-ID reads. The loader warns above `0x800` bytes. |
| `0x800` | `modelAnimationOffsets[8]` | `modelLoadAnimations` requests 16 bytes from `MODANIM.TAB`, then reads the first signed halfword. |
| `0x800` | `animationMapOffsets[8]` | Both AMAP readers request 32 bytes at `(modelId & ~3) * 4`, then subtract words `index + 1` and `index`, with `index = modelId & 3`. |
| `0x810` | Opaque tail alias | The initializer stores this address in `lbl_803DCB5C`; no current consumer establishes a role for its contents. |

The eight-word AMAP transfer crosses the `+0x810` alias. These are overlapping
views, not independent buffers. The union retains all `0x30` tail bytes while
describing only the observed read windows; it does not assign a table capacity
from the next pointer's address. Size and offset assertions establish the
allocation extent and both published scratch addresses. Allocation and I/O
sizes now derive from these records. The global pointers keep their proven
storage types and declaration order, and the signed overflow comparison is
preserved. Its warning still does not prevent an oversized load.

EN v1.0 retail `ObjModel_InitResourceCaches` (`0x800296A4`) requests `0x830`
bytes and publishes offsets zero, `0x800`, and `0x810`. Its entire normalized
instruction body, plus those of `modelLoadAnimations` and `modelGetAmapSize`,
agrees with checksum-verified EN rev1, JP, and PAL rev1. The locally available
EN rev1, JP, and PAL resource sets also contain identical `MODANIM.TAB`
(2,528 bytes) and `AMAP.TAB` (5,056 bytes). Their largest adjacent spans are
1,716 and 34,320 bytes respectively. This is corroborating sibling-resource
evidence, not a claim about absent EN v1.0 assets or PAL rev0.

The complete compiled model object remains byte-identical, including all 85
functions, allocated sections, symbols, and relocations. The recovery introduces
no regional source conditions or compiler changes and does not increase match
scores. The initializer and AMAP sizing function remain exact; the animation
loader retains its existing register differences.

Fresh compilation and objdiff checks for EN, EN rev1, JP, and PAL rev1
preserve each target's model report and the common object SHA-256
`e2240860057452c42d5a2074315a7d1b3da3917d2eb9c2d54ac0d9c7e782b74a`.
Formatting preserves those same bytes. EN `all_source` and the strict retail
checksum build pass within their 30-second limits.

## Instance buffer sizing and layout (2026-10-06)

EN `modelLoad_calcSizes` at `0x80025880` and `modelLoad_layoutBuffers` at
`0x80025AE4` share a 0x1C-byte size record. `ModelInstanceSizes` replaces the
anonymous seven-integer arrays in both callers and the raw +0x14 access in
the calculator. Its six used fields have explicit offset assertions:

| Offset | Field | Budget |
| --- | --- | --- |
| `0x00` | `geometryBytes` | Dynamic vertex buffers plus optional normal buffer, including their existing alignment allowances |
| `0x04` | `hitSphereBytes` | Two runtime hit-sphere buffers |
| `0x08` | `unused08` | Four opaque bytes, neither read nor written by this pair |
| `0x0C` | `moveCacheBytes` | Four move-cache slots per animation state, doubled with load flag `0x80` |
| `0x10` | `stateBytes` | One or two animation states, plus three morph channels when requested |
| `0x14` | `moveCacheSlotBytes` | One variable-length move-cache allocation, rounded up to eight bytes; only written in cached-animation mode |
| `0x18` | `jointMatrixBytes` | Two joint-matrix buffers, with the retail no-animation fallback |

The corresponding Dinosaur Planet `ModelStats` record and `modGetStats` /
`createModelInstance` pair corroborate the seven-word layout and the roles of
the six used words. The names here follow SFA consumers: for example the state
budget includes animation states as well as optional morph channels, and the
geometry budget includes normals. Donor names alone do not establish those
roles. Foxhollow's layout function also corroborates the buffer order and typed
pointer stores; its native alignment adjustments are separate port changes.

The layout function now takes a `ModelFileHeader*`, returns an `ObjModel*`, and
carves buffers with a byte cursor. Pointer fields are assigned through their
declared types instead of `int*` aliases. Separate animation-state and morph
locals replace the reused byte-pointer casts. Header fields, record sizes and
chunk element widths replace the repeated header casts and several literal
strides. The allocation base remains a byte pointer until its model view is
needed; that source shape preserves retail's two live base registers without
the previous `pointer | pointer` expression.

The retail contract has several deliberate limits:

- Matrix sizing tests `animationCount`; it does not use the separate joint-count
  fallback in the matrix accessor.
- Joint-work budgeting requires `jointData`, `jointCount` and `unk18`; carving
  also requires `unk1C`. Their different predicates are preserved.
- `firstInstance` is passed as `file->refCount == 1` but is unused by this layout
  function. Optional fields that retail leaves untouched are still untouched;
  this function does not clear the destination allocation.
- The alignment functions retain their target integer-address ABI. A byte
  cursor and typed stores do not by themselves establish a 64-bit native loader.

All five verified targets retain the exact 612-byte calculator, 1,108-byte
layout function, 300-byte model loader and complete 85-function model TU.
The model object changes only 34 anonymous literal-symbol numbers: section
bytes, symbol offsets and normalized relocations are identical. Every other
source object is byte-identical. Complete objdiff reports have no new
discrepancies, retaining the existing two library accounting exceptions.
All five full-source builds and strict source-linked DOL checksum checks pass.
The native texture/load probe uses the recovered size-record type at its stub
boundary and still passes its 945 shader cases and 20 load paths at both
optimization levels under ASan/UBSan; it does not execute the layout function.
Formatting is separate and preserves all source object hashes.

## Initial animation state and release (2026-10-06)

`modelAnimResetState` (EN `0x80024EC8`) now takes the canonical model and
animation-state types. Its four initial-move loads use a typed inline helper
instead of `MODEL_LOAD_INITIAL_MOVE`, which captured the caller's `hdr` local
and converted each cache pointer to `u32`. `modelLoadInitialMove` keeps the
cache pointer intact, and `animLoadFromTable` receives a `ModelFileHeader*`.
The reset path selects `ObjAnimMoveData` directly and reads its `frameControl`
field at the evidenced unsigned-byte width before storing the signed high
nibble in `frameType`.

The helper preserves the two existing paths and their file-lock gate:

| Input | Behavior |
| --- | --- |
| Non-null private cache | Load into its `moveData` payload and joint-slot prefix through `animLoadFromTable` |
| Null cache, shared-resource miss | Query the ANIM size, allocate and decompress it, set reference count one, then insert it in the shared cache |
| Null cache, shared-resource hit | Increment its reference byte |
| PI locked, model ID other than 1 or 3 | Skip resource acquisition |

The null-cache branch retains its original acquisition side effects without
installing a pointer into the caller's slot. The helper returns no value, just
as the old macro supplied none. This reconstruction does not infer a new
fallback assignment or fix that path's behavior. Reset still leaves unrelated
state fields and padding untouched, and only the zero high-nibble frame mode
subtracts one from the frame count.

`ObjModel_Release` (EN `0x80029368`) now takes an `ObjModel*` and uses its typed
file owner. It releases per-instance shader references and the render attachment
before decrementing the shared file reference. Only the last file reference
releases model textures, shared move resources and the file itself. Move-pointer
table traversal now uses `sizeof(ObjAnimMoveData*)`; the target stride stays
four bytes and native pointers are no longer traversed with a four-byte stride.
The function does not free the instance allocation. The signed test of a
decremented animation reference byte is retained, including its wraparound
behavior. Its existing two-element loop-counter local remains: scalar and
direct-index rewrites changed the exact retail register flow.

`python3 tools/test_model_animation_lifecycle.py` executes the production helper,
reset and release functions with canonical records and pointers above 4 GiB.
At both `-O0` and `-O2`, ASan/UBSan checks 216 acquisition cases, 768 reset cases
and 432 release cases. Spies verify asset/cache call order, all four private
cache addresses, lock exceptions, null move entries, texture decoding,
reference counts, and exact release order. Whole-record comparisons verify
untouched state and header bytes. IO, texture decoding and deallocation are
stubbed; this is not a complete native game loader. Negative-control builds
restoring cache-pointer truncation or the four-byte native move-pointer stride
both fail the probe.

The full model TU stays at 100% in EN, EN rev1, JP, PAL and PAL rev1, including
the 1,368-byte reset function and 380-byte release function. Only 46 anonymous
literal symbols are renumbered at unchanged positions; code, section contents
and normalized relocations are identical. Every other source object is
byte-identical, including the single shared-consumer edit in `object.c`.
Full objdiff reports retain only the two existing library accounting exceptions.
All five full-source builds and strict source-linked retail DOL checks pass;
the separate formatting change preserves every source object hash.
