# Text-box texture loops

`gameTextInitBoxTextures` at EN `0x8001C794` creates two RGB5A3 textures from
linear halfword images: a 16x16 corner and a 20x20 edge. Both are stored in GX
4x4 tiles. The source images are `u16 [16][16]` and `u16 [20][20]` arrays in
`textrender_drawbox.c`, occupying exactly 512 and 800 bytes in retail.

The function matches at 100% under the common `cflags_dll_noopt` profile.

## Recovered source shape

- Both images are indexed as two-dimensional arrays,
  `src[tileRow * 4 + texelY][x]`, with no named row pointer.
  The row address is an IRO-hoisted temporary, created before any live-range
  split object, so the edge loop colours it ahead of its destination and row
  counter (`r10`, `r11`, `r12`).
- One set of loop locals serves both images. The IRO splitter keeps the corner
  loop's live ranges on the named objects and gives the edge loop's ranges new
  generated objects. The edge row counter is therefore above the value-numbering
  cutoff: its zero seed is shared with the derived row offset (`li r12,0;
  mr r9,r12`), while the corner's named counters keep separate `li`s.
- The corner walks tiles with `tileColumn++`; its live unit counter is the
  retail `r30`. The edge walks `tileLeft += 4` over pixel columns, a named
  local used only there. That keeps the edge column induction on a named object
  that is coloured between `tileColumn` and `assetCount`, giving `r30`.
- Declaration order follows GC/1.3 colouring: named locals receive virtual
  registers in reverse declaration order and are coloured in declaration order,
  each taking the lowest free colour and otherwise claiming `r31`, `r30`,
  `r29` in turn. `dst` first gives the corner destination `r12`; `tileRow` and
  `tileColumn` then claim `r31` and `r30`; `textureSlot`, `textureAsset` and
  `assetCount` finish as `r30`, `r31` and `r29`.

## Checks

`python -m unittest discover -s tools -p test_gametext_box_textures.py` compiles
the production TU with host-native texture storage and controlled allocator,
asset-loader, and cache dependencies. It checks every texel against an
independent linear-coordinate-to-tile-index oracle: one coordinate pattern,
32 randomized image pairs, and the retained texture assets. Header bytes, guards
on both sides, the background texture, and source images remain untouched. The
test also checks load/allocate/flush order, all allocation parameters,
published pointers, and exact flush ranges.

The `textrender_drawbox.c` object is byte-identical with the two-dimensional
array declarations.
