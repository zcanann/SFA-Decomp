# Model animation loading

`modelLoadAnimations` at EN v1.0 `80025420` now uses the canonical
`ModelFileHeader` and signed animation-ID arrays. The first group base is
written through `animGroupBaseIndices`; each `-1` ID establishes the next
group's base at the following index. This removes the raw `+0x70` store and
the one-element byte-offset array without changing the retail loop.

The loader has two distinct resource paths:

- With `MODEL_FLAG_CACHED_ANIMATIONS`, the caller's buffer retains the
  `MODANIM.BIN` ID list, padded to eight bytes. Animations are subsequently
  fetched through the move-cache path. `animationModelPtrs` is cleared.
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
