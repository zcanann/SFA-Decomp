# Sparse model morph targets

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

The old `modelApplyBoneTransform`, `modelBoneTransforms_next`, and
`modelApplyBoneTransforms` names describe vertex morphing, not joint transforms.
The caller `ObjModel_ApplyBlendChannels` selects two entries from
`ModelFileHeader.morphTargetPtrs` (+0xdc) using the channel's target indices,
then supplies the base and instance vertex buffers and `vertexCount`.
The three routines are now `modelBlendMorphTargetChunk`, `modelReadMorphDelta`,
and `modelBlendMorphTargets` respectively. Their EN addresses and TU remain
unchanged.

Each stream is a variable-length sequence of halfwords. The header's low 13
bits give a vertex index; bits 0x2000, 0x4000, and 0x8000 select the following
signed X, Y, and Z delta halfwords, in that order. Omitted components are zero.
The decoder reads the flags unsigned, while the blend loop retains retail's
signed header load before masking the index. A fixed-size record would give
the wrong stride. The pointer table, relocation, channel selection, cache
wrapper and decoder now share the `u16*` stream contract.

An absent target uses a local one-halfword stream containing `vertexCount + 1`.
This out-of-range index requires no component payload. Both cursors are written
back after each chunk, so a target record for the next chunk remains pending.
The cache wrapper's 0x2a0 limit counts **vertices**; the separate transfer counts
are 32-byte cache blocks. The global and locals now distinguish those units.

The blend weight has 16 fractional bits and may be negative: the channel code
allows weights down to -1, applies signed easing, and multiplies by 65536.
Retail combines each component with `mullw`, `add`, `srwi 16`, and `sth`.
Accordingly, the C multiplies and adds as unsigned 32-bit values before taking
the high halfword and adding the base coordinate. Casting only the old signed
expression's final result was too late to prevent C signed-overflow undefined
behavior. For example, a -32768 delta times a -65536 weight exceeds `int`.
This change defines the retail wraparound without changing the generated PPC.

Validation:

- All 85 function bodies, allocated sections and symbol positions are unchanged
  after accounting for the four semantic symbol renames. Relocation destinations
  are unchanged; 67 anonymous compiler-generated relocation names are renumbered.
- All 1,001 other source objects remain byte-identical, and the complete objdiff
  report is unchanged apart from the three function names. The private-ABI pair
  remains 10.784483% / 10.833333%; the cache wrapper remains exact.
- `python3 tools/test_model_morph_blend.py` executes production source bodies
  against a dense, unlimited-precision Python oracle: 135 scenarios each at O0
  and O2, covering all component masks, empty streams, signed extremes, negative
  weights, zero vertices and cursor continuation across the 672-vertex boundary.
  Signed-overflow sanitizer checks pass. Running the same fixture with the old
  source catches the overflow. The harness does not exercise the retail private
  register ABI, cache DMA or asset loading.
- The strict retail checksum and `ninja all_source` pass.

Retail's decoder passes its cursor through r20 and returns deltas through
r10/r12/r15. Ordinary C still uses pointer output parameters and the normal EABI;
these names and types do not resolve that code-generation mismatch.
