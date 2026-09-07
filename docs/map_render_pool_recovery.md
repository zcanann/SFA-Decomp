# Map-rendering TU and pool recovery (2026-09-07)

The shared map-rendering `.sdata2` pool is now exact. The five artificial
fragments `shader`, `lightmap`, `lightmap_initmapblocks`, `lightmap_draw`, and
`tex_dolphin` have been reunited in `src/main/shader.c`, in retail function order.
All 40,656 assigned data bytes match. The common GC/1.3 invocation produces
136/145 exact functions and a 99.488594% instruction fuzzy score; the TU remains
`NonMatching` because nine functions still differ.

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

The subsequent code pass restores four functions without changing their sizes
or any other function's generated instructions:

- `renderSceneGeometry`: initialize the horizontal cursor alongside the row's
  minimum X before computing the cell pointer. Keep the row bound and moving
  cursor as separate locals.
- `collectShadowTrackTriangles`: select the triangle flag with an explicit
  branch and declare the triangle count before the descriptor pointers. The
  compiler trace confirms the ternary introduced a temporary that colored
  ahead of the loop's persistent registers.
- `mapBlockRender_setShader`: read the three packed instruction bytes with
  offsets from an unchanged base pointer. This removes the mutable pointer web
  responsible for the final register swap.
- `mapInstantiateObjects`: correct `MapEventInterface.getMapAct` and its inline
  wrapper to take `int`, matching `SaveGame_getMapAct`, then restore the cursor,
  end pointer, and object-index declaration order. Dolphin's `s32` is `long`
  under MWCC; the old interface introduced an int-to-long conversion temporary.
  Comparing all 2,684 compiled objects before and after the interface correction
  found no changes outside this function in `shader.o`.

The GC/1.3 backend decoder now also recognizes the observed `andc`, `srw`, and
`psq_lx` records. They were validated against captured final instruction streams
and emitted ELF instructions. The diagnostic captures passed the ordinary versus
instrumented full-object hash gate, and their register graphs replayed without
high-degree removals.

A second code pass restores three more functions:

- `updateEnvironment`: separate inline routines update texture animations and
  texture scrolling. The animation routine uses a native indexed array walk;
  the scroll routine retains its byte cursor. Inlining makes the zero
  initializers eligible for commoning, and the local declaration order restores
  both the integer and floating-register assignments.
- `renderGlows`: ordinary `f32` locals retain zero and one across the FIFO
  writes, removing sixteen extra literal loads. Making those locals `const`
  reinstates the extra loads under the shared GC/1.3 profile. The render-flag
  test also keeps the retail signed comparison. The function and its complete
  pool-load sequence are now exact.
- `initMapBlocks`: initialize all five layers through the existing typed buffer
  view, then clear 120 ROM-list page pointers with one ordinary loop. MWCC
  supplies the forty-store unrolling that was previously handwritten. The
  page cursor is typed, and the existing two-part base-address expression is
  retained because collapsing it changes the address temporary's register.

The old `lightmap` and initializer fragments depended on extra `noprop` and
`nocse` flags. They now share shader's existing `nopeephole,noschedule` /
`-inline noauto` profile and the required common game compiler. No compiler
exceptions, per-function pragmas, or section-alignment overrides were retained.
The initial merge exposed six formerly exact functions: `updateVisibleGeometry`,
`renderObjects`, `renderSceneGeometry`, `initMapBlocks`, `renderGlows`, and
`queueGlowRender`. Three other functions became exact, so that merge changed the
combined exact function count from 132 to 129. The follow-up passes bring it to
136. All nine remaining code differences must be recovered before
`MatchingFor` is justified.

All forty functions that directly consume this pool now have matching literal
value sequences. This includes `renderGlows`, whose extra zero/one loads were
removed in the second code pass.

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
