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

## Called axis helpers close the pool (2026-09-09)

The unit now fully matches all five retail versions: 26 functions, 19,800 code
bytes and 1,216 data bytes. The missing pool order comes from two called private
helpers, `lightningSetReferenceZAxis` and `lightningSetReferenceXAxis`.

Both strand and bolt rendering choose an X or Z reference axis before building
their perpendicular basis. The helpers replace those four repeated three-store
blocks. Their calls inline under the common `cflags_dll_noopt` profile, preserving
the complete retail instruction streams. Their emitted out-of-line copies
introduce zero and one before `lightningGetRemainingFraction` introduces its
integer-conversion biases. The Z-axis helper precedes the X-axis helper because
its zero/zero/one stores supply the evidenced zero-before-one pool order.

This removes the unit's `noauto` restriction while retaining GC/1.3 and its
existing optimization settings. Keeping `noauto` produces real calls to the
helpers and regresses both lightning renderers. Explicit `inline` under that
profile preserves code but omits the early pool contribution. Deferred inlining
also changes the cloud-update code and emits an additional early constant; it
is not retained. Ordinary automatic inlining gives both exact callers and the
complete 232-byte pool, replacing the former 240-byte generated pool. Other
allocated data and global storage layouts remain unchanged.

No uncalled seed body, invented data, padding, source split or compiler-version
exception is needed. The helper names and decomposition are inferred from the
duplicated axis stores and validated by their code and pool output; they are
not recovered original identifiers. This resolves the historical phantom-body
proposal in `priced_classes.md` with source helpers that have real callers.

For each hash-verified version, objdiff with completion annotations disabled
reports every function and data section exact. An all-retail control link and
a link substituting only this source object both reproduce the original DOL.
Both helper bodies exist in the object and are absent from the final linked
ELF. Native matching and `all_source` builds pass, and every unrelated source
object remains byte-identical. EN is marked matching in `configure.py`; the
four secondary progress manifests each gain the verified unit. Each version
gains one completed unit and 232 matched data bytes, with no new function-match
credit because the 26 functions were already exact.

Sources, compiler controls, full objdiff reports, isolated links and build logs
are under `/tmp/sfa-lightning-axis/` locally.
