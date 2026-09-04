# Engine 0: HUD declaration and source-shape recovery

EN v1.0, 2026-09-04. The unit is `src/dlls/engine/0/0.c`, containing the
command menu, HUD, communicator, and pause menus. It remains `NonMatching`
with the existing GC/2.0, `-inline noauto` profile.

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

## Grid interpolation

In `pauseMenuDrawGridCell`, spelling the two interpolation terms as
`pr / 512.0` instead of `pr * 0.001953125` reproduces the retail fused
multiply-add operand order. The function improves from 99.545456% to
99.624504%, with the same 253 instructions. Register differences remain.

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

## Remaining leads, not closed compiler walls

- **Resource loader:** EN reloads three object pointers immediately after
  storing them. GC/2.0 forwards the just-stored value in the current source.
  GC/1.3 reproduces the complete loader exactly in an isolated compiler
  probe. However, it changes other functions, including turning the
  `hudDrawCounter` function-pointer cast into an indirect call where retail
  calls directly. Signed `char` and unsigned assignment masks explain some
  additional version differences, but do not establish the TU's original
  compiler. Keep the existing profile until independent provenance or a
  coherent whole-unit reconstruction resolves this.
- **Release:** only three instruction words differ, all using `r26` where
  retail uses `r27` for the initial texture iterator. This is a much smaller
  residual than the older worklist records.
- **Constant ownership:** target `.sdata2` is 980 bytes; source emits 936.
  Eight currently external constants have values absent from the emitted
  pool: `gGameUiPi`, `lbl_803E1F30`, `lbl_803E1F34`, `lbl_803E209C`,
  `lbl_803E20B8`, `lbl_803E2128`, `gPauseMenuPodiumBaseY`, and
  `gPauseMenuRingScale`. Replacing them with literals changes constant
  folding and breaks previously exact functions. Appending named constant
  definitions does not recover the pool layout either. Their ownership
  model remains unresolved; do not force sections or duplicate literals.

## Validation

| Measure | Before | After |
| --- | ---: | ---: |
| Exact functions | 104 / 118 | 105 / 118 |
| Exact code bytes | 44,208 / 75,188 | 44,840 / 75,188 |
| TU fuzzy match | 99.79481% | 99.80385% |
| Exact assigned data bytes | 8,972 / 9,952 | 8,972 / 9,952 |

The baseline is commit `e4b437c778`. The TU formatting pass preserves the
raw object hash of the combined source changes. Function boundaries,
compiler configuration, and data declarations remain unchanged. All six
non-text sections retain their bytes and sizes, and all non-text global
symbols retain their offsets and sizes. Comparing 2,682 pre-existing source
objects after the builds finds only engine 0 changed.

Use the normal object build and objdiff report, plus
`python3 tools/fnbytes.py 0 hudDrawCommunicatorAlert`, to reproduce the
function comparison. The strict EN checksum build and `ninja all_source`
both pass within their 30-second limits. Formatting checks also pass.
The strict build still uses retail code for this `NonMatching` TU and is
not proof that the remaining thirteen functions match.
