# Font metrics and string measurement

`gameTextMeasureString` now uses `const FontMetrics*` and typed array indexing
for its active font. The former byte pointer, repeated casts and hard-coded
16-byte stride obscured a record already shared by measurement, wrapping,
rendering and the system-font atlas builder. Local names now distinguish the
encoded byte cursor, Unicode code point, control arguments, font ID and scaled
metric values. The public prototype names the two optional maximum outputs
as font width and line height rather than glyph advance.

The record's layout is now asserted beside its definition:

| Offset | Field | Evidence |
| --- | --- | --- |
| `00` | `glyphCount`, u16 | System-font atlas initialization stores its selected glyph count here. |
| `06` | `colorMode`, u8 | Renderer loads this byte and compares it with 1 before selecting its color path. |
| `08` | `maxWidth`, u16 | Atlas construction tracks its widest glyph; measurement loads and scales this field. |
| `0A` | `lineHeight`, u16 | Measurement and wrapping load and scale this field. |

Retail indexing establishes a `0x10`-byte record. Other bytes retain their
existing opaque descriptions. In particular, the atlas builder's writes at
`04` and `05` do not by themselves establish what those fields mean.

The renderer's former `unk06` is named `colorMode`. Mode
`GAMETEXT_FONT_COLOR_TEXTURE` (1) uses white RGB and the current text alpha for
normal drawing, followed by a texture-times-color TEV stage. Its shadow path
uses black RGB. Other values use the selected text RGB and the existing text
TEV setup. The comparison remains explicitly `== 1`; the table also contains
0 and 2, so this byte is not treated as a Boolean.

## Measurement behavior retained

The routine decodes UTF-8 and consumes control arguments as big-endian 16-bit
values stored in its existing integer scratch array. It recognizes font and
fixed-point scale changes, looks up each glyph in the selected font, and sums
`scale * (advanceX + width + offsetX)`. Missing glyphs and face-font glyphs add
no width. Removing the redundant character-pointer local and combining the
two skip guards preserves the generated instructions.

The optional maxima are **font metrics**, not the dimensions of glyphs actually
encountered. They initialize from the selected non-face font and increase only
when a font command selects a larger scaled metric. A scale-only command
changes later glyph advances but does not refresh those maxima. A face-font
selection skips both metric initialization/update and width accumulation.
The optional second scalar output is still written as zero on normal return;
a null input returns before touching any output. None of these quirks is
normalized into different measurement behavior.

## Remaining match gap

The EN measurement function remains 94.58253%, with 305 source instructions
against 309 retail instructions. The structural diff shows shared `.data`
base addressing replacing retail's separate symbol-address materializations,
plus a control-table cursor-address difference. Typed font access does not
resolve those compiler differences. The [confirmed gametext TU](gametext_tu_recovery.md)
remains intact and retains its compiler profile.

The existing 16 gametext tests pass, covering neighboring lookup, bounds,
resource layout, colors, initialization and loading behavior. They do not
directly execute this string-measurement routine; its preservation is checked
by comparing every generated function byte, allocated data section, named
storage layout and normalized relocation target before and after the change.

The checks pass for EN v1.0, EN revision 1, JP and PAL revision 1; each
retail DOL passes its configured SHA-1. Their measurement and rendering
functions have identical normalized retail instruction signatures. All four
source objects are identical after the recovery, with SHA-256
`d9e40083294e933d778e14542a2933b397c1529a912fb4e569d3d666c96b00df`.
Objdiff function scores and unit measures remain unchanged in every version.
The `all_source` builds pass in 23.81, 23.72, 22.84, 21.33 seconds respectively.
