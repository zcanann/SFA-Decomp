# Morph-channel refresh state

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

`ObjModelBlendChannel.previousWeight` at +0x04 records the weight observed by the
preceding apply pass. It is compared with `weight` to request a refresh and
updated from `weight` at the end of the pass; it is not a destination weight.
Target selection initializes it to -1 to invalidate that comparison. Automatic
advancement instead adds `weightRate * dt` to `weight`.

The byte at +0x0e is now `flags`, with these recovered meanings:

| Bit | Name | Retail behavior |
| --- | --- | --- |
| 0x01 | `MANUAL` | Skip automatic weight advancement. |
| 0x02 | `RESET_WEIGHT` | Reset the weight to zero during the apply pass. |
| 0x04 | `DIRTY` | Refresh now, then set 0x08. |
| 0x08 | `REFRESH_NEXT` | Refresh once more, then clear this bit. |
| 0x10 | `KEEP_WEIGHT` | Preserve weight when changing target indices. |
| 0x20 | `ALLOW_NEGATIVE` | Permit the apply-time weight range [-1, 1], rather than [0, 1]. |

The renderer toggles the vertex-buffer selector immediately before applying
channels. The two refresh bits therefore update both alternating output
buffers. They do not describe a fade approaching `previousWeight`. Changing the
weight restarts the 0x04 -> 0x08 -> 0 sequence, and the explicit weight setter
requests it even when given the current value.

`ObjModel_NeedsBlendChannelUpdate`, formerly `ObjModel_HasActiveBlendChannels`,
tests the weight comparison and pending bits 0x0e. Selected morph targets can
remain active while this query returns zero. The title-screen consumer uses
that idle condition before selecting another target. Vertex animation can
separately force the renderer to refresh steady channels.

Channel 1 overrides channel 0. Channel 2 is additive: it uses the selected live
vertex buffer when a base channel is active, otherwise the file's base vertices.
A change in either layer requests recomposition of the other active layer.
Consequently `previousWeight` is a cached observation, not proof that a channel
was applied: suppressed channel 0 still receives the bookkeeping update.

Tricky sets 0x21 and drives channel 1 with `2 * blendWeight - 1`, establishing
manual signed weights. The space-thruster and slot-470 callers set 0x10 while
requesting positive/negative rates. Those callers now use the canonical flags.
The target setter's floating-point argument is named `weightRate`, and the
automatic-advance API uses `ObjModel*` directly at both object-update calls.
Setting identical target indices still returns without applying a new rate or
flags; clearing targets retains the two-pass base-restoration behavior.

Validation: all 85 model function bodies, allocated sections, named symbol
positions and relocation targets are unchanged after the two semantic symbol
renames. The title-screen call uses the renamed query; all other 1,000 source objects
are byte-identical. The complete objdiff report is unchanged
apart from the renamed query. The strict retail checksum and `all_source` pass.

`python3 tools/test_model_blend_channels.py` executes seven production functions
and their real channel definition at O0 and O2. Each run checks 22 apply passes,
including alternating outputs, refresh restart, manual/automatic rates, signed
clamps, channel priority, additive recomposition, target clearing and rejected
target changes. A call recorder replaces the morph kernel to inspect source,
destination, target and weight selection; the separate morph-stream tests cover
that kernel's arithmetic. These host tests do not execute cache DMA or drawing.
