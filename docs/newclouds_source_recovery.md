# Newclouds Global Storage Recovery

The GC/1.3 game baseline at `8492378c94` matched 25 of the 26 functions in
`dlls/engine/7/7.c`. `newclouds_run` had the same 594 instructions as retail,
with four operand differences. Its source simulated the compiler's shared BSS
base with a texture-array pointer, an artificial layout struct, a byte offset,
and accesses beyond the texture array.

## Recovered Accesses

The update loop now uses `gNewCloudLayerTextures`, `&gNewClouds[cloudIndex]`, and
`gNewCloudSnowFlashDirection` directly. The last symbol is the existing 16-byte
`lbl_8039A8F0` allocation: its first three floats hold the transformed downward
direction passed to `drawSnowFlashOverlay`. The fourth word remains unaccessed;
this change neither assigns it a role nor changes the allocation.

The cloud, wind-source, and flash-direction definitions are now beside the snow
simulation functions, before the update loop, instead of at the end of the TU.
The texture array remains with the rendering code. This makes the definitions
visible when MWCC compiles the update loop, allowing it to generate its own
shared BSS base. Earlier users retain their forward declarations. No compiler
profile, section directive, or synthetic function is needed.

Definition visibility matters independently of object identity. Moving all four
definitions to the top of the TU also enabled a shared base, but swapped the
cloud and texture arrays. Moving the last three only before `newclouds_run`
instead placed the flash direction before the wind sources. Neither experiment
was retained. The chosen grouping preserves every named offset:

| Object | BSS Offset | Bytes |
| --- | ---: | ---: |
| Layer textures | `0x00` | `0x10` |
| Cloud pointers | `0x10` | `0x20` |
| Wind sources | `0x30` | `0xa8` |
| Flash direction storage | `0xd8` | `0x10` |

These results supersede the expression-only limit recorded for this function in
`priced_classes.md` and `source_shape_levers.md`: the missing input was the
compiler's knowledge of the actual global definitions, not another spelling of
the fabricated base-plus-offset expression. The placement is a tested source
reconstruction, not proof of the original declaration lines.

## Verification And Remaining Gap

- All 26 functions match retail, including all 594 update-loop instructions.
- The other 25 functions remain byte-identical to the baseline object.
- Every allocated non-text section remains byte-identical to the baseline.
- Named data offsets, sizes, alignment and linkage are unchanged apart from the
  flash-direction symbol rename.
- `ninja all_source` and the strict retail DOL checksum pass.

The unit remains `NonMatching`: its generated `.sdata2` is still 240 bytes
against retail's 232. Retail's early `1.0f` precedes the first function's two
conversion biases; the current source emits it later. Simple lifetime-fraction
promotion expressions leave both code and pool unchanged. No dead helper or
forced constant was added to fill the gap. Matched data remains 984/1216 bytes;
matched code increases from 17424/19800 to 19800/19800.
