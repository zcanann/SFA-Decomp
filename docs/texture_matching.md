# Texture frame and GX header recovery

The September 6–7 measurements below are historical, from baseline
`5065408724`. The current texture TU is fully matching under GC/1.3 in all
five configured versions; the earlier `NonMatching` experiments are no
longer its build state. See the October 6 recovery below for current evidence.

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

## Retained N64 texture rendering data (2026-10-06)

The texture TU's 4,400-byte data span beginning at EN `0x8030D058` contains
47 RDP command arrays, 52 rendering presets and seven eight-command mipmap
tile setups. It previously represented the presets as 208 integers, including
104 pointer-to-integer casts, and left the command arrays under address labels.
`TextureRdpCommand` now models each eight-byte command as two words;
`TextureRdpPreset` models the two command-array pointers, render-flag mask
and forced flags. Assertions retain the retail 0x10-byte preset layout.
The tile setup block remains one allocation, expressed as `[7][8]` commands.

The evidence is stronger than similar names or nearby data. Expanding the
GBI macros in `../dinosaur-planet/src/texture.c` produces every word of all
47 arrays and all seven tile setups exactly. Every preset also has the same
ordered command-array references and scalar fields. The inspected reference
is commit `c4340802dc9f62e1181d00cc34c3175fca6ca4be`; the audit fingerprints
its actual source and relevant headers so local changes cannot be confused
with commit provenance.

The reference's `texDPTextureSimple` and `texDPTextures` consumers establish the
selection contract: `(renderFlags & renderFlagMask) | forcedRenderFlags`
selects an other-mode command, and that result shifted right three selects
the combiner's fog variant. The reference MIPS listings corroborate the C:
a 16-byte preset stride, mask/OR loads at +8/+0xC, and command-array loads
at +0/+4. The four retained flags mean anti-aliasing, Z comparison,
translucency and fog. The source now names those flags and
uses descriptive command-family names, including decal, cutout, trilinear
and untextured variants. These are evidence-based descriptions, not a claim
to have recovered original SFA identifier spellings or a GC RDP consumer.
Separate arrays with identical contents remain separate definitions and
retain their original preset references.

Run `python3 tools/texture_rdp_audit.py --all-versions` to compile the actual
source data with native pointers and compare every command, preset pointer
and scalar against each hash-verified original DOL. Adding
`--reference ../dinosaur-planet` independently expands the donor's GBI macros
and verifies the complete ordered correspondence. The audit also checks all
832 combinations of preset and low render flags, including the consumer's
fallback translucent index. Four scratch negative controls reject a changed
command word, redirected preset pointer, changed forced flag and changed
tile command.

The entire texture object preserves section contents, sizes, alignment,
symbol positions and relocation targets after the 48 explicit symbol
renames. Every other source object remains byte-identical. All five versions
pass `all_source` and strict retail DOL checksums; the texture TU's 17
functions, 6,308 code bytes and 5,296 data bytes remain 100% exact. The full
active-unit inventory has no new mismatches; the existing SDK/MusyX report
accounting exceptions remain unchanged.

## Typed texture archive headers (2026-10-06)

The three frame readers in `pi_dolphin.c` now use the complete 16-byte
`ZlbHeader` and its 12-byte `ZlbStreamInfo` suffix. The suffix starts after
the four-byte tag and contains the version, decompressed size and compressed
size. This models the retail cursor at header +4 without integer-address
laundering or unexplained `+4`/`+8` dereferences. Full-header users retain
size fields at +8/+12. The layout assertions cover both views; existing ZLB
payload-loader accesses use the same definition. These are descriptive types,
not a claim to recovered original declarations.

Archive and table slots now use the canonical MLDF IDs. The previously unused
`TEX_TAB_MAP_A`/`TEX_TAB_MAP_B` definitions were reversed: A is `0x40000000`,
B is `0x80000000`. This agrees with the readers and the merged-table policy.
A keeps its signed literal type, which preserves the retail signed zero
comparison. There were no existing uses of either macro before this change.

The distinct reader behavior is retained. TEX1 can read an explicitly selected
missing bank from DVD when the other bank is resident. Its table-based fallback
requires a resident BIN; TEX0's does not. Only non-indexed TEX1/TEXPRE queries
interpret `DIR` as compressed size -1. The indexed TEX1 path writes its size
outputs in the opposite order from TEX0/TEXPRE, including when outputs alias.
States with no usable selection remain the existing caller precondition.

`test_resource_buffer_registry.py` now adds 592 cases for selection priority,
in-flight snapshots, DVD fallback, unknown modes, null offset tables and aliased
outputs to its 790 existing cases. Both optimization levels pass with ASan and
UBSan and native addresses above 4 GiB. Four negative controls detect reversed
bank selection, a wrong size field, omission of the terminal offset and taking
the load-state snapshot after restoring interrupts. The other resource-loader,
merge and defrag fixtures also pass after adapting to the shared metadata type.

The complete `pi_dolphin` TU is 100% exact in all five versions: 57 functions,
32,252 code bytes / 111,432 data bytes in EN/JP and 32,384 / 111,400 in the
other versions. Object comparisons preserve every section byte, named symbol
offset, relocation and section attribute; one anonymous pool symbol is
renumbered. Every other source object is byte-identical to the baseline.
All five `all_source` builds and strict source-linked retail DOL checks pass.
Full objdiff inventories retain only the pre-existing TRK vector-carving and
MusyX discarded-exception report artifacts; no unit regresses.
