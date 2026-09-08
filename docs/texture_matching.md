# Texture frame and GX header recovery

EN v1.0 (`GSAE01`), September 6, 2026. Baseline: `5065408724`.
The texture TU remains `NonMatching` under the existing GC/1.3 profile.

## Recovered contracts

`textureLoad` extracts bits 29..24 of a texture bank word, reads a table
of frame offsets, and decompresses each frame into a separate `Texture`.
It links those records through `nextAnimationFrame` and stores the first
record's frame count shifted left eight bits. The animation update and
frame-selection functions consume that fixed-point count. These are
animation frames; the mip levels are independently read from the header's
`minLod` / `maxLod` bytes at 0x1C / 0x1D by the GX initializers.

The frame-query API names now distinguish the single header, indexed
header, and offset-table queries. Header outputs at offsets 8 and 12 are
the decompressed and compressed sizes. The direct-data path reports -1
instead of a compressed size. `texPreGetFrame` replaces the misleading
`texPreGetMipmap` name, including its symbol entries in the other version
configs. These names describe evidenced behavior, not recovered source
spellings; the validation below covers EN v1.0 only.

`Texture.gxTexObj` is a native `GXTexObj` at offset 0x20 rather than an
anonymous eight-word array. Its address is passed to the GX texture
initialization, selection, and rendering APIs. The complete header remains
0x60 bytes. Direct consumers now take the member's address, and the layout
assertions cover both mip-level bytes as well as the existing member offsets.

## Code generation

The loaded-texture lookup and free-slot searches use native indexed loops.
MWCC generates the retail pointer induction and register assignments itself;
the explicit source pointer iterators produced additional register differences.
The initializer uses a scalar `GXBool` rather than a one-element byte array,
and takes a `Texture*` parameter directly.

| Measure | Before | After |
| --- | ---: | ---: |
| `textureLoad` fuzzy match | 98.88199% | 99.15114% |
| `textureInitGXTexObj` fuzzy match | 98.42696% | 97.97753% |
| Texture TU fuzzy match | 99.37857% | 99.43564% |
| Exact functions | 14 / 17 | 14 / 17 |

Removing the artificial byte array adds one initializer instruction and
changes register allocation. The loader still lacks one register copy and
three trailing branches present in retail. `loadTextureFiles` also lacks
three trailing branches. Neither compiler settings nor TU boundaries were
changed to conceal those differences.

All other texture function instruction bytes are unchanged. Texture data
section bytes, sizes, alignments, named symbol offsets, and data relocations
are unchanged. All other units retain their baseline objdiff measures.
`tex0GetFrame`, `tex1GetFrame`, and `texPreGetFrame` still match retail
instruction bytes exactly (440, 720, and 244 bytes respectively).

Validation: `python3 configure.py --matching`, the default `ninja` retail
checksum target, and `ninja all_source` pass, with each ninja invocation
limited to 30 seconds. The checksum uses the retail object for this
`NonMatching` TU; objdiff and direct object comparisons establish the source
results above.

## Native diagnostic references and bank walks (2026-09-07)

`texRestructRefs` now passes its named diagnostic arrays directly to `OSReport`.
It previously obtained every format by adding offsets as large as 0x1420 to
`sRcpTexRestructStrings`, which was actually a 16-byte graphics-command array.
That source pointer arithmetic crossed unrelated objects and hid the diagnostics'
real ownership. The compiler now forms the shared data base itself.

The former pseudo-string is named `gRcpTextureCombineCommands` and expressed as
four `u32` words, consistent with the adjacent command tables. Its two repeated
64-bit commands begin with opcode 0xfc (`G_SETCOMBINE` in the N64 SDK header,
corroborated by `reference_projects/fzerox/include/PR/gbi.h`). The existing
preset table still references this same 16-byte allocation twice. No further
meaning is assigned to the remaining imported command words or preset fields.
The active symbol config records the new name and word interpretation.

Ordinary definitions are reordered for deferred emission, retaining the common
GC/1.3 compiler, disabled automatic inlining, and existing optimization settings.
EN initialization follows its consumers in text, and the direct diagnostics
reproduce the retail common-base instructions exactly. Together these support
this emission model; it is not a recovered historical build command. The two
native BSS definitions are ordered so bank counts remain at offset zero and
bank-table pointers at offset 0x0c. Zero-filled section comparisons alone would
have missed their displacement in the initial experiment.

`loadTextureFiles` now counts entries with indexed accesses for all three banks,
removing the manually advanced table/count pointers. The sentinel and count-minus-
one behavior are unchanged. Every one of the seventeen functions retains its
complete instruction bytes, including the fourteen already-exact functions.
All allocated section bytes, sizes, and alignments are unchanged; every named
layout is unchanged apart from the command-array rename. The preset relocations
still resolve to the same command bytes. Match scores are unchanged, and the TU
remains `NonMatching` for its three outstanding functions. This pass improves
source structure and ownership rather than claiming additional matched code.

Both `ninja all_source` and the strict matching checksum pass with 30-second
limits. The DOL remains byte-identical to retail, using this incomplete TU's
retail object. A separate object audit confirms unchanged function and section
bytes, all named layouts after the single rename, and every relocation's resolved
section/offset or external-symbol destination. No runtime behavior change is
claimed or needed for this recovery.

Formatting is a separate commit. The active TU and its canonical header pass
`clang-format --dry-run --Werror`, and the formatting pass preserves the complete
compiled object byte for byte.
