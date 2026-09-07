# Typed models in skeleton collision queries

Target: EN v1.0 (`GSAE01`), game compiler GC/1.3.

The two skeleton-hit collectors now receive `ObjModel*`, and the pair
coordinator passes `ObjHitsSkeletonHit*` throughout. The former integer-array
model view was the active model instance: word zero is `file`, and word five
is `skeletonJointData` at +0x14. Both accesses now use the canonical fields.
The collector declarations and response declarations in `objhits.h` agree
with their definitions and callers.

The response routines also receive the instance's `ModelFileHeader*`.
Neither routine reads that argument in EN v1.0, so its name is
`unusedModelFile`; the argument remains present in the ABI. The additional
scratch arguments to `ObjHits_CheckSkeletonPair` remain opaque and are
forwarded unchanged when it retries the pair with reversed objects.

The old response calls copied every argument into short-lived aliases,
including an integer round trip for the object pointer. Passing the actual
typed arguments directly restores the retail ordering of the object and hit
list register moves relative to the joint-data, file, and best-hit loads.
The type recovery alone is byte-identical; removing these aliases changes
only the pair coordinator's instructions.

The existing behavior is preserved, including two distinct scale ratios:
the 3D branch divides by object A's hitbox scale times A's root-motion scale,
while the XZ branch divides by A's hitbox scale times B's root-motion scale.
The ratio clamp, response component clamps, shape selection, mode checks,
and single reversed-pair retry are unchanged. The XZ denominator is not
normalized to match the 3D spelling.

`ObjHits_CheckSkeletonPair` improves from 96.792114% to 99.6595%, retaining
its 1,116-byte size. The remaining instruction differences exchange r30 and
r31 for the model and object B's collision state. Existing literal-pool
differences described in `objhits_literal_recovery.md` also remain.

Validation: only the pair coordinator's instruction bytes change within
`objhits.o`; named symbol positions, non-text sections, and relocation
records are unchanged. The other 1,001 source objects are byte-identical,
and every other function retains its size and match score. The existing
capsule-normal host suite passes (it exercises the geometric helper, not
pair routing). Both the strict retail checksum and `ninja all_source` pass;
the unit remains NonMatching, so the strict link uses its retail object.
