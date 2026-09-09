# Model render records

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

`ModelFileHeader` now owns typed records for the adjacent render metadata at
+0x40 through +0x54. Relocation, matrix preparation, and fuzz rendering use
those definitions; no serialized offsets or record sizes change.

## Extra joints

`modelCalcVtxGroupMtxs` at `0x8003befc` walks `extraJointDefs` (+0x54) with a
four-byte stride, explicitly advanced at `0x8003c124`. `ModelExtraJointDef`
therefore contains two byte-sized joint indices, a byte-sized first-joint
weight, and one unknown byte. The earlier header comment incorrectly described
three-byte records. The count remains `extraJointCount` at +0xf4.

The first weight is `weightA / 4.0f`; the second is `1.0f - firstWeight`.
Each input joint matrix is first translated by the negative inverse-bind tail
from its `ModelBone`. The weighted sum of all twelve matrix components is
written to the extra matrix at `jointCount + groupIndex`. No range restriction
or meaning for the fourth byte is inferred. The source now indexes both the
extra-joint records and bone records natively.

## Fuzz expansion

The old `jointBlendData` pointer at +0x40 is `jointFuzzScales`: one
`ModelFuzzScaleDef` per joint, with three pivot floats followed by a scale
divisor, stride 0x10. The same shape is embedded at +0x44 as `vertexFuzzScale`
for the vertex-animation render path. The previous claim that the pointer
was passed to the vertex blend stream came from an unrelated instance/header
overlay; the recovered stream instead uses `ObjModel.vertexAnimOffsets`.

The joint loop in `modelDoRenderInstrs` at `0x80040814` uses the divisor to
compute `gObjFuzzStep * (fade / scaleDivisor) + 1`. When the existing pivot-bypass flag
is clear, translation to the negative pivot precedes scaling and translation
back follows it. The vertex-animation path uses its embedded pivot and the
scale `1 + 1.5 * (gObjFuzzLayerIndex + 1) * fade / scaleDivisor`. These matching
access patterns justify a shared 0x10-byte record without assigning an
unproven physical meaning to the divisor.

The renderer uses native array indexing; separate byte-offset counters are
removed. Layout assertions cover both record sizes, their known fields, and
the three model-header offsets.

Validation: all 85 model function bodies and all 32 renderer function bodies
are unchanged, as are allocated section contents, named symbol positions,
and relocation destinations. The model object and the other 1,000 source
objects are byte-identical; 55 renderer relocation records have renamed
anonymous compiler symbols only. The complete objdiff report is unchanged:
`modelCalcVtxGroupMtxs` remains 636 bytes at 99.15094%, and
`modelDoRenderInstrs` remains 3,160 bytes at 99.94304%. The strict retail
checksum and `all_source` both pass. The extra-joint helper's remaining diff
is register allocation, not a record-layout or arithmetic mismatch.

## Renderer input and stream types

The main instruction renderer, material-state setup, and vertex-descriptor
decoder now carry `ModelFileHeader`, `ObjModel`, `Shader`, and
`ModelRenderOpTextureRefs` directly. The material lookup reads
`activeModel->file`; its two optional textures use the existing record fields
instead of an integer-array overlay. Five renderer callers pass the model
header without converting it to a byte pointer.

The vertex animation input, output, and GX position array select the existing
`ObjModel.vtxBuf` members directly. The no-hit-volume path decrements
`ObjHitReactState.resetHitboxMode` through its owning header, preserving the
unsigned byte store, signed test, and subsequent object-state reload. No state
size or field signedness changes.

All renderer bitstream consumers now use `ModelRenderInstrsState`, the same
0x14-byte record accepted by the initializer. The duplicate `MtxBitStream`
definition and its three-word padding claim are removed. `instrs` and `bit`
retain offsets 0x00 and 0x10; the intervening count fields and still-opaque
`fieldC` remain owned by the canonical header. Matrix roles, the owner argument,
and the skin-matrix-ready flag are named without splitting local lifetimes.

This is source recovery, not a new code match: all 32 function bodies,
allocated section contents, named symbol layouts, and resolved relocation
destinations remain unchanged. Compiler-generated constant labels renumber;
the complete ELF is therefore not byte-identical. `shader.o`, the internal
header's only other source consumer, is byte-identical when compiled against
the old and new header. Objdiff remains 99.87762% for the unit, with 24/32
functions exact. Both `all_source` and the strict retail checksum pass.
