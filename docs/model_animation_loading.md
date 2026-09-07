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
and derives a byte span from adjacent offsets. The first view now uses an
explicit `s16*` local. The existing parameter reuse for the AMAP byte span
and the separate buffer cursor are retained: separating the span or using
the buffer parameter directly changes register allocation. Cache locals are
named for animations rather than texture atlases.

The existing overflow diagnostic, group-table writes, reference-count
signedness, and error cleanup are preserved. The change adds no new bounds
checks or allocation behavior. The zero-animation case still performs its
initial table read before returning.

All 85 model function bodies, allocated section bytes, and named symbol layouts
remain unchanged under GC/1.3. The loader remains 944 bytes at 99.66102%; its
remaining retail differences exchange the registers used for the byte span
and buffer cursor. Anonymous symbol names change without changing normalized
relocation destinations. Separate formatting preserves the complete object.
The strict retail checksum and `all_source` builds validate the canonical
declaration and its direct caller.

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
