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

Validation of the initial C recovery (before register-ABI reconstruction):

- All 85 function bodies, allocated sections and symbol positions are unchanged
  after accounting for the four semantic symbol renames. Relocation destinations
  are unchanged; 67 anonymous compiler-generated relocation names are renumbered.
- All 1,001 other source objects remain byte-identical, and the complete objdiff
  report is unchanged apart from the three function names. The private-ABI pair
  remains 10.784483% / 10.833333%; the cache wrapper remains exact.
- `python3 tools/test_model_morph_blend.py` executed the then-production C source bodies
  against a dense, unlimited-precision Python oracle: 135 scenarios each at O0
  and O2, covering all component masks, empty streams, signed extremes, negative
  weights, zero vertices and cursor continuation across the 672-vertex boundary.
  Signed-overflow sanitizer checks pass. Running the same fixture with the old
  source catches the overflow. The harness does not exercise the retail private
  register ABI, cache DMA or asset loading.
- The strict retail checksum and `ninja all_source` pass.

## Register interface recovery (2026-09-07)

The retail decoder accepts and advances its stream cursor in r20, returns signed
X/Y/Z deltas in r10/r12/r15, and uses r21/r22 as scratch. It neither receives
ordinary pointer-output parameters nor preserves the EABI nonvolatile registers
it modifies. Its parent calls it four times and saves r14–r31 itself. Ordinary C
with pointer outputs cannot express that separately callable private interface.
This is compelling evidence for an assembly-level contract; it does not establish
whether the original author wrote assembly or used another compiler mechanism.

The active goal permits justified guideline exceptions when compelling evidence
exists. The narrow exception recorded in `AGENTS.md` covers these two functions
only. They now preserve the evidenced interface in MWCC assembly, with semantic
labels and register roles documented beside the source. The C cache/DMA wrapper,
TU boundary, compiler profile and matching status remain unchanged.

The ordinary-C reconstruction is retained in
`docs/foreign/model_morph_reference.c` as an executable specification. Its
unsigned arithmetic defines low-word wraparound. It describes valid sorted,
sentinel-terminated streams; it does not reproduce every memory read (retail
loads pending headers even for a zero-vertex chunk). It is reconstructed code,
not a recovered source artifact from the disc.

Validation:

- Both routines match all retail instructions: 116/116 for the 464-byte chunk
  blender and 18/18 for the 72-byte decoder.
- `python3 tools/test_model_morph_blend.py` tests the C reference at O0/O2 with
  signed-overflow sanitization, using 135 dense-oracle scenarios per build.
- `python3 tools/model_morph_emulation_probe.py` (optional `unicorn` and
  `pyelftools` dependencies) executes the compiled object and retail DOL
  separately against the same independent arithmetic oracle. Each runs 135
  blending scenarios plus 16 direct decoder cases covering all component masks.
  Checks include output guards, unchanged inputs, stream cursor continuation,
  stack restoration, preserved GPRs, CR2–CR4 and LR. The decoder is checked using
  its private register contract. Cache DMA, malformed assets and hardware timing
  are outside this probe's scope.
- Objdiff raises the pair from 10.784483% / 10.833333% to 100% / 100%,
  adding 536 exact code bytes and moving this TU from 74 to 76 exact functions
  out of 85. These are the only function-score changes in the full report.
- The other 83 function bodies, all non-text section bytes, named data symbol
  layouts and resolved relocation destinations are unchanged. Later text symbols
  move because the pair is smaller; relocation comparisons account for those
  function offsets. All 1,001 other source objects are byte-identical.
- Deliberately changing the compiled decoder's X-presence mask makes the PPC
  probe fail. The unmodified compiled object passes.
- `python3 configure.py --matching`, `ninja -j64 all_source` and the strict
  retail-checksum target pass, with each Ninja invocation limited to 30 seconds.
