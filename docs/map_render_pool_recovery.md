# Map-rendering TU and pool recovery (2026-09-07)

The shared map-rendering `.sdata2` pool is now exact. The five artificial
fragments `shader`, `lightmap`, `lightmap_initmapblocks`, `lightmap_draw`, and
`tex_dolphin` have been reunited in `src/main/shader.c`, in retail function order.
All 40,656 assigned data bytes match. The common GC/1.3 invocation produces
129/145 exact functions and a 99.218056% instruction fuzzy score; the TU remains
`NonMatching` because sixteen functions still differ.

This supersedes the constant-pool blocker in
[lightmap_draw_recovery.md](lightmap_draw_recovery.md) and the historical
compiler-profile rejection in [dll_naming_manifest.md](dll_naming_manifest.md#yield).
The previous 29 drawing functions remain exact inside the combined TU.

## Retail boundary evidence

The unit occupies EN `.text` `0x80054F64..0x80061094`. Its pool occupies
`0x803DEBB0..0x803DEC58`. There are 151 direct r2-relative loads into that pool,
all within the combined text range. Constants such as `640.0f`, `0.5f`, and
`0.125f` are shared across the former file boundaries. The adjacent texture and
shadow units use separate pools. Compiling the combined source now reproduces
the complete pool's values, order, alignment, and named scale-symbol offset.

The stored filename `shader.c` is retained. Disc source-leak and source-matrix
searches did not establish an original filename for this span. Dinosaur Planet's
map source supplies related algorithmic structure, not proof of SFA's filename.

| Section | EN start | EN end | Assigned bytes |
|---|---|---|---:|
| `.rodata` | `0x802C1E58` | `0x802C1EA8` | 80 |
| `.data` | `0x8030E4B0` | `0x8030E864` | 948 |
| `.bss` | `0x8037E0C0` | `0x803879B0` | 39,152 |
| `.sdata` | `0x803DB620` | `0x803DB648` | 40 |
| `.sbss` | `0x803DCDC8` | `0x803DCED4` | 268 |
| `.sdata2` | `0x803DEBB0` | `0x803DEC58` | 168 |

## Source and storage recovery

Ordinary float expressions replace external declarations that merely named
compiler literals. Dividing packed coordinates by `8.0f`, the indirect matrix
scale by `2.0f`, and flare size by `256.0f` recovers the target reciprocal literals
and operand order. The initial white word is a real `GXColor` copied by shader
texture setup.

`gTexIndMtxScale` is a stored `0.0625f` at pool offset `0x74`. Reading it through a
local `const f32*` preserves its single allocation. Reading the same-TU constant
directly makes MWCC retain the named word and emit a duplicate anonymous literal.
The pointer's scope is the matrix-scale calculation, and the function remains
exact. No synthetic section declarations or padding objects are used.

The source emits 164 pool bytes; the linker supplies four bytes of alignment.
The two internal zero alignment words are at `0x803DEBBC` and `0x803DEC44`.
Neither those words nor the trailing word at `0x803DEC54` has a direct retail
load. The actual shared floating zero is at `0x803DEBCC`.

The render queue now has 1,000 typed 16-byte entries, matching its runtime flush
threshold, followed by an opaque 200-byte tail. Assertions retain the existing
`0x3F48` allocation and the tail's offset. The tail is not promoted into extra
queue capacity. BSS definitions are collected in the compiler's reverse
allocation order so all sixteen native BSS objects retain their retail offsets.
The audit also checks the other named data symbols; zero-filled section equality
alone would not catch their displacement.

The native layer-search loop in `mapSetup` and the indexed page walk in
`mapRomListFindItem` replace an unrolled search and an array-of-one cursor.
Both functions now match exactly. `beginLoadingMap` also becomes exact in the
combined unit. Native queue accesses preserve the drawing functions and reduce
the `renderObjects` mismatch.

## Remaining source-link blockers

The old `lightmap` and initializer fragments depended on extra `noprop` and
`nocse` flags. They now share shader's existing `nopeephole,noschedule` /
`-inline noauto` profile and the required common game compiler. No compiler
exceptions, per-function pragmas, or section-alignment overrides were retained.
This exposes six formerly exact functions: `updateVisibleGeometry`,
`renderObjects`, `renderSceneGeometry`, `initMapBlocks`, `renderGlows`, and
`queueGlowRender`. Three other functions became exact, so the combined exact
function count changes from 132 to 129. These code differences must be recovered
before `MatchingFor` is justified.

`renderGlows` also reloads the zero/one literals more often than retail across
the FIFO-writing helpers. The pool values and addresses are correct; the load
sequence is not. The other 39 functions that directly consume this pool have
matching value sequences.

Two zero fog-color records at `.sbss2` `0x803E8444` and `0x803E8448` remain retail
externs (`gTexShaderFogColor` and `gTexLightmapFogColor`). Their declaration and
emission order has not been recovered. They are not claimed by this change;
forcing either record into `.sdata2` or `.sbss` would misrepresent its storage.

The regional `version_progress.py <version> --write` refreshes were attempted
for EN rev1, JP, PAL, and PAL rev1, but their DOLs are absent in this checkout.
Only their already-established fragment claims were merged; no regional pool
claim, symbol projection, or new match was inferred. The deleted initializer's
stale matching-unit entries were removed.

## Verification

`python3 tools/map_render_data_audit.py` checks 40,656 assigned data bytes,
118 common native symbol layouts, 40 jump-table relocations including their
function-relative destinations, the unique stored scale, and all 151 direct
retail pool loads. It compares the pool against the original DOL as well as the
regenerated retail object. Deliberately corrupting a literal and moving the
queue symbol in separate scratch objects both correctly fail the audit.
MWCC's writable ELF flag on `.sdata2` differs from the reconstructed retail
ELF's flag; the audit permits that compiler metadata difference, which has no
DOL representation, while checking type, allocation, and alignment.

`ninja all_source` and the strict matching build pass with 30-second timeouts.
The matching DOL remains byte-identical to the prior retail build. This gate
still links this TU's retail object and is not a claim that its source-linked
DOL is exact. Formatting is committed separately and checked to preserve the
complete generated object; the TU and its internal header pass
`clang-format --dry-run --Werror`.
