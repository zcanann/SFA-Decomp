# Engine 0: HUD declaration and source-shape recovery

EN v1.0, 2026-09-04. The unit is `src/dlls/engine/0/0.c`, containing the
command menu, HUD, communicator, and pause menus. It remains `NonMatching`.
The September 4 pass reached 106 of 118 exact functions; the September 5
follow-up below starts with 108. All 118 have the retail instruction count.
The whole TU uses GC/1.3, `-inline noauto`, and signed `char`.

## Color declarations and the compiler fingerprint

`gameTextSetColor` is implemented with four `u8` channels in
`src/main/textrender_gettext.c`, but Game UI previously saw four `int`
parameters. Recovering that byte contract also lets `hudDrawCounter` accept
`u8 alpha` and call `drawTexture` directly, removing its incompatible
function-pointer cast. Float expressions pass directly to the narrow
parameters; the score-screen pulse locals are bytes. These changes preserve
every baseline function's instruction bytes under GC/2.0.

The two local pause-menu texture helpers similarly accept `u16 scale`.
Their implementations already consumed the low 16 bits. Removing the old
intermediate integer conversions in their callers preserves their code.
The shared color header has a Game UI opt-in, so other callers retain their
existing declarations.

The resource loader provides evidence beyond an aggregate compiler score:
retail reloads three communicator object pointers immediately after storing
them. With the same source, GC/1.3 emits those loads and matches all 896
bytes. GC/1.3.2, GC/1.3.2r, and GC/2.0 forward the stored pointers. The older
compiler's previous indirect-call regression in `hudDrawCounter` disappears
with the corrected declaration; retail's direct call is now reproduced.

GC/1.3 preserves all 105 previously exact functions and fixes the loader.
It also removes the extra instruction in `drawViewFinderHud`, improving that
function from 99.36948% to 99.4498%. Signed `char` preserves the existing
byte comparisons. Unsigned compound-assignment masks preserve the retail
operations on `gCMenuButtons`; comparison masks retain their original types.
This supports the compiler profile without claiming a recovered historical
build script or changing the confirmed TU boundary.

## Status-page call recovery

The scarab counter's format is `"%d/%d"`. Its reconstructed `sprintf` call
omitted the capacity argument. Retail's `lbz r6` supplies that argument and
also tests whether the capacity is zero. Passing `gPauseMenuScarabCapacity`
restores both instructions.

The spellstone count is one sum of four `mainGetBit` calls, in the same
source order used by the other menu logic. MWCC emits the retail call and
addition order from that expression; the manually staged count temporaries
were changing its registers. Together these fixes improve
`pauseMenuDrawStatusPage` from 99.85141% to 99.91085%. Twelve instruction words
still differ, all in the alpha registers.

## A solved residual: communicator pulse rendering

`hudDrawCommunicatorAlert` now matches all 632 bytes / 158 instructions.
The previous 99.05064% implementation carried explicit locals for fade,
horizontal offset, vertical position, alpha, and scale. Those locals
reproduced the calculations but obscured the compiler's common expressions
and loop strength reduction.

The matching source has only two signed-byte locals: pulse phase and
segment index. Both draw calls repeat their coordinate, alpha, and scale
expressions. Alpha is `255 - segment * 85`; MWCC creates the descending
170, 85, 0 induction variable itself.

The decisive declaration is the texture-drawing scale argument. Game UI's
existing narrow-alpha API view also needs **`u16 scale`**, alongside
`u8 alpha`. With an `int` scale declaration, explicit `(u16)` casts make
MWCC share the already-truncated scale across calls, introducing two extra
copies. With the narrow declaration, MWCC shares the untruncated arithmetic
and emits the retail conversion at each call.

This is supported by the renderer implementations in
`src/track/intersect_render.c`: all three texture-drawing routines consume
scale as `u16`. The reconstructed renderer definitions still use wider
parameters; the matching caller view does not by itself prove which
historical header declared those definitions. The shared header therefore
retains its default view, and the existing Game UI opt-in now describes
both narrow arguments as `INTERSECT_HUD_NARROW_ARGS`.

One other Game UI call needed its recovered conversion corrected:
`hudDrawButtons` passes the Y-button animation scale directly as a float
expression. Its old intermediate `(int)` cast adds an unwanted mask under
the narrow declaration. Removing that cast restores its previous code
exactly. Every other function preserves its baseline match, apart from the
independent grid interpolation improvement below.

## Grid interpolation and pulse

In `pauseMenuDrawGridCell`, spelling the two interpolation terms as
`pr / 512.0` instead of `pr * 0.001953125` reproduces the retail fused
multiply-add operand order. The function improves from 99.545456% to
99.624504%, with the same 253 instructions. Register differences remain.

The pulse reflection now uses a conditional expression, narrowing the reflected
value inside that expression before multiplying by the fade step. This reproduces
retail's instruction and branch sequence, improving the function to 99.68379%.
All 253 instructions remain; register differences still prevent an exact match.
The other 117 function bodies, data contents, relocations, and named symbol
offsets are unchanged. The exact-function count remains 106 / 118.

## Dinosaur Planet comparison

The substantive predecessor is
`../dinosaur-planet/src/dlls/engine/1_cmdmenu/cmdmenu.c`. Its file comment
records the debug-side name `9slcommandmenu.c`. Useful counterparts include
`cmdmenu_page_load_items`, `cmdmenu_store_loaded_item_metadata`,
`cmdmenu_draw_player_stats`, and `cmdmenu_dtor`.

The N64 implementation confirms parallel item tables, indexed loops, and
the inventory/sidekick distinction. It is an earlier implementation:
the GameCube communicator, Arwing HUD, pause-menu additions, and duplicate
item-clear passes cannot simply be copied from it. Natural indexed rewrites
of the current C-menu loader, including separate-array probes, did not
reproduce the EN pointer and register structure. No sibling files were
changed.

## Constant ownership and remaining work

Three former external constants are now emitted by their consumers:
the backdrop's `f32` scale of 435.2, the podium's `f32` base Y of -2.1,
and division by 1024.0f for the ring transforms. These preserve every
instruction byte. The float locals preserve the retail loads and conversion
precision; substituting literals directly can instead fold the conversion
or change the precision of an intermediate constant.

The source `.sdata2` grows from 936 to 948 bytes toward the retail 980.
Its fuzzy match improves from 97.28601% to 97.92531%. No duplicate named
constants or explicit section placement are needed.

- **Release:** only three instruction words differ, all using `r26` where
  retail uses `r27` for the initial texture iterator.
- **Constant ownership:** five external constants remain absent from the
  emitted pool: `gGameUiPi`, `lbl_803E1F30`, `lbl_803E1F34`,
  `lbl_803E20B8`, and `lbl_803E2128`. Their values plus pool alignment
  account for the remaining size difference. Replacing them with literals
  or float locals changes folding, conversion reuse, or register allocation.
  Appending named definitions puts them in `.sdata`. Their source ownership
  remains unresolved; do not force sections or duplicate literals.

## September 4 validation

| Measure | Before communicator fix | After communicator fix | Current |
| --- | ---: | ---: | ---: |
| Exact functions | 104 / 118 | 105 / 118 | 106 / 118 |
| Exact code bytes | 44,208 / 75,188 | 44,840 / 75,188 | 45,736 / 75,188 |
| TU fuzzy match | 99.79481% | 99.80385% | 99.82806% |
| Exact assigned data bytes | 8,972 / 9,952 | 8,972 / 9,952 | 8,972 / 9,952 |

The current pass starts at commit `2793989679`. All non-pool data sections
retain their bytes, sizes, and named symbol offsets. GC/1.3 changes five
data relocations from named arrays to section-plus-offset references; they
resolve to the same locations. Comparing 2,682 pre-existing source objects
after the builds finds only engine 0 changed.

Use the normal object build and objdiff report, plus
`python3 tools/fnbytes.py 0 hudDrawCommunicatorAlert`, to reproduce the
function comparison, or substitute `gameUiLoadResources` for the loader.
The strict EN checksum build and `ninja all_source` both pass within their
30-second limits (about 16 seconds each). Formatting checks also pass.
The strict build still uses retail code for this `NonMatching` TU and is
not proof that the remaining twelve functions match.

## September 5 follow-up

A fresh build at `4d84859649` already uses GC/1.3 and has 108 exact
functions, including the subsequently matched `GameUI_release` and
`hudDrawMagicBar`. This pass preserves that compiler profile and TU boundary.

The C-menu count-label loop now derives its row offset from `i * 50`.
MWCC generates the induction variable itself, bringing `hudDrawButtons`
from 99.666664% to 99.68513%. The head-display scanline computes and saves
its Y coordinate in the first draw call, matching retail's placement of
the calculation after loading the texture and X coordinate.
`headDisplayDraw` improves from 98.802086% to 99.21875%.

The TU code fuzzy score rises from **99.85679% to 99.86833%**. Exact code
remains 48,544 / 75,188 bytes across **108 / 118 functions**. All 118
functions retain the retail instruction count, and no function's score
regresses. Only the two edited functions change instruction bytes.

All six data sections retain their source-object bytes, sizes, alignment,
and resolved data relocations. Every named symbol retains its size and
offset. MWCC renumbers anonymous pool and switch-table symbols after the
head-display edit; their layouts and contents remain unchanged.

The TU is still `NonMatching`: ten functions have residual differences,
and `.sdata2` still emits 948 of the retail pool's 980 bytes. Direct literal
substitutions for the five missing constants change code generation; they
were not retained. Declaration and scope probes also failed to eliminate
the remaining differences. No partial compiler profile, forced section, or
additional TU split is used.

Validation: `python3 configure.py --matching`, strict default `ninja`, and
`ninja all_source` pass within the required 30-second timeout per build.
Formatting checks pass for the TU and its public API header. The strict
checksum still links retail code for this `NonMatching` TU.

## September 5 complete constant-pool recovery

The next pass starts at `0cd820cb40` and resolves the pool ownership left
open above. All eleven references to TU-owned compiler literals now use
their correctly typed values. Five values were missing from the source
pool: float pi, 80.0f, 320.0f, 256.0f, and double 1/256. Six others were
already emitted anonymously but still had external references in the C.
The source now emits the complete **980-byte `.sdata2`**, including the
retail alignment, with no duplicate named constants or forced sections.

Float locals for the status icons, hint panel, grid cursor, and carousel
retain retail's conversion precision and operand order. The timed HUD
element uses a compound alpha update. These spellings preserve the exact
functions that direct literal substitutions initially changed.

The map and head-display shimmer calculations combine their two sine
waves in one expression. This preserves the retail call order and restores
the floating-point registers. The viewfinder line helper computes its
corner offsets in the draw-call arguments, improving the grid's temporary
registers. `headDisplayDraw` rises to 99.302086%; the viewfinder remains
below its previous score at 99.36948% after the literal recovery.

| Measure | Previous | Current |
| --- | ---: | ---: |
| Exact functions | 108 / 118 | 108 / 118 |
| Exact code bytes | 48,544 / 75,188 | 48,544 / 75,188 |
| Code fuzzy match | 99.86833% | 99.865135% |
| Exact assigned data bytes | 8,972 / 9,952 | **9,952 / 9,952** |

All 118 functions retain their retail instruction counts. Existing
exports, non-pool data layouts, and resolved data relocations are
unchanged. An undefined-symbol audit of the 1,042 active target objects
finds no other TU consuming the eleven former literal symbols. Old build
objects outside the active config are excluded from this audit.

A diagnostic link replaces only engine 0's retail object with the rebuilt
GC/1.3 object. It succeeds with no missing symbols, preserves every linked
section address and size, and reproduces every linked data section byte
for byte. Only `.text` differs: 563 bytes across the ten remaining
non-exact functions. Thus the small code-fuzzy regression accompanies a
complete, independently linked data recovery.

Validation: strict checksum `ninja` and `ninja all_source` both exit 0
within their 30-second limits. Formatting checks pass for the TU and
`include/main/dll/dll_0000_gameui_api.h`. The TU remains `NonMatching`;
the diagnostic source link does not yet reproduce the retail DOL.
