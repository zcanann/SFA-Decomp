# Bone-Particle Renderer Recovery

Target: EN GSAE01, `src/dlls/engine/24/24.c`, common game GC/1.3 profile.

## Retail Data

The renderer at `0x800A433C` uses one compiler-generated data-pool base. Separate
private arrays reproduce that base and the complete 1,832-byte `.data` section;
an encompassing configuration struct is not required. Previously the C indexed
past `gBoneParticleConfigTable` into three separately declared globals. Those
accesses are now ordinary typed table indexing, with no section directives or
force-active entries for the former anonymous tables.

- Three coordinate planes begin at offsets `0`, `0x90`, and `0x120`. Each retains
  twelve initialized vectors (three identical quads). The renderer consumes only
  the first quad in each plane; the other copies are retained, not assigned new
  behavior.
- Twenty `LightmapVertex` templates begin at `0x1B0`.
- Forty-two `LightmapTriangle` records begin at `0x2F0`. The first 32 join four
  pairs of adjacent four-vertex rings. The final ten are two caps per ring. Only
  the first 32 are submitted to the draw function.
- The plane lookup starts at `0x590`. The seven-by-five joint-ID table at `0x5B4`
  selects IDs up to 33, so 34 plane entries suffice. The two remaining zero bytes
  and the zero byte after the joint-ID table are naturally emitted alignment.
  This establishes the accessed extent, not a proven original plane-array bound.
- XY and Z scales start at `0x5D8` and `0x664`. The two initialized 35-float
  sequences are retained separately. Entry 34 in each is unreferenced by the
  recovered joint groups; the array sizes do not establish a model joint count.
- The descriptor remains at `0x6F0`, size `0x38`, with unchanged callbacks.

`python tools/bone_particle_data_audit.py` verifies the initialized section against
the retail object, named table offsets, descriptor relocations, triangle topology,
plane coordinates, and joint lookup bounds. It deliberately does not certify the
renderer code or `.sdata2` pool.

## Code And Remaining Differences

Direct `GameObject`, `LightmapVertex`, `Vec3f`, and `PartFxSpawnParams` accesses
replace the former byte object, duplicate vertex type, float cursors, and short
spawn-packet casts. The registry includes the owning header and casts only at its
generic resource boundary; its complete object SHA256 is unchanged:
`5f9b93e30cb97dd5972ca89a2c1c8183d30c53c4f5e85bca76fb49892bdd14fb`.

The initial table recovery produced the retail 441-instruction structure, with only
register differences (61 operand rows). Previously it had 442 instructions,
including an extra move, and 11 operand rows. TU fuzzy match changes from
99.77438% to 99.49054%; the other seven retail functions remain exact. This is a
source-recovery checkpoint, not a percentage gain. No compiler flags changed.

The renderer's unusual matrix access is preserved: it advances by sixteen
`MtxPtr` rows per joint and reads translation from row three. The ordinary
per-joint spawning function instead obtains its matrix through
`ObjModel_GetJointMatrix`. Do not silently normalize the renderer's stride.

The unused `boneParticleEffect_resetDrift` helper was introduced by `d47f5e5ce4`
solely to manufacture an earlier literal-pool group, removed by `db867c3aa7`, then
restored in `dd06905c7b` without a caller or retail body. It is removed again.
The real compiler output is now the correct text-section size (`0xABC`), without
that extra dead body. Ordinary local zero/one initialization under GC/1.3 does
not recover the pool order:

```
retail:   0, 500, -1, -500, 1, 20.02, 8, 0.0495
current:  500, -1, -500, 0, 1, 20.02, 8, 0.0495
```

This loses the 32-byte `.sdata2` section's exact credit; it does not change the
initialized configuration data. Keep the TU `NonMatching` while recovering the
real source explanation. `ninja all_source` and the strict retail DOL checksum
pass with these changes.

## Matrix Rows And Buffer Capacity

The follow-up uses `MtxPtr` for the renderer's matrix rows and reads translation
as `jointMatrix[3][0..2]`. It retains the sixteen-row step per joint; replacing
that with a conventional one-matrix step would change behavior. Declaring the
model before the loop locals together with this typed row access reduces the
update function's differing operands from 61 to 53. Its 441-instruction structure
is unchanged, fuzzy match rises from 99.20635% to 99.29705%, and TU fuzzy match
rises from 99.49054% to 99.54876%. The other seven functions remain byte-exact.

The buffer array now contains seven pointers, matching the seven allocation
calls, update/draw iterations, and release iterations. Each allocation holds
twenty `LightmapVertex` records; its size is expressed through that type. The
former eighth pointer was never accessed. The generated BSS is 28 bytes with
eight-byte alignment, accounting for the entire 32-byte retail span once linked.
The symbol config records the 28-byte array rather than including the four-byte
alignment tail in its size. `bone_particle_data_audit.py` now checks this storage
extent and padding explanation as well as the initialized tables.

All initialized data and the literal pool are unchanged, and the unit retains
1904/1936 matched data bytes. Both build gates pass. This is a partial source and
codegen gain, not a newly exact function or a solution to the literal-pool gap.
