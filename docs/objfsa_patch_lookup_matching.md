# Objfsa patch lookup

`Objfsa_GetPatchGroupIdAtPoint` in `dlls/engine/20_Hcurves/Hcurves.c`
matches all 73 instructions (292 bytes) in EN, EN revision 1, JP, PAL, and
PAL revision 1 under the existing common GC/1.3 compiler and optimization
profile. Each unit now has 18 of 19 exact functions.

The lookup rejects patches outside their open Y interval, then tests the four
X/Z half-planes in order. A point on a plane is accepted; a positive plane
expression rejects it. The private inline `objfsaFindRejectingPatchPlane`
returns the rejecting plane index, or four when all planes accept the point.
This is a source-structure reconstruction, not evidence of an original helper
name. Keeping the Z and X declarations in that order reproduces the retail
floating-point register assignment after inlining.

The earlier extraction removed ten register-operand differences, reaching
99.178085%. Initializing `planeIndex = 0` and then copying it into
`normalComponentIndex` in a separate statement recovers the final retail
`mr r7,r8`; the chained assignment emitted `li r7,0`. The neighboring
`objfsaExitOutside` already uses this scalar initialization pattern.
No compiler flags, storage layouts, or TU boundaries change.

Only this function's instruction bytes change. All other function bodies,
allocated non-text sections, named-symbol layouts, and resolved relocations
are unchanged across all five versions. Each input DOL was checked against
its configured SHA-1, and the five retail lookup instruction bodies are
identical. The existing 72-byte literal-pool ordering mismatch and the
remaining `Objfsa_UpdateWalkGroupPatches` mismatch are unaffected.
Objdiff remains the measure of the reconstructed source;
the strict matching link uses the retail object while this unit is NonMatching.

Validation: `python3 configure.py --matching`, `ninja -j64 all_source`, and
strict `ninja -j64`, each with a 30-second timeout. The resulting matching DOL
is byte-identical to the EN v1.0 retail DOL. Formatting is committed separately
when it produces a diff, and checked for unchanged generated object bytes.

## Walk-group patch construction and reset

The updater now names its two-group scratch pairs, reciprocal edge search,
plane normals, patch search, and exit-point adjustment roles explicitly. The
map-flag buffer uses the existing `ROM_LIST_PAGE_COUNT`; link-slot byte cursors
use the canonical curve field offsets and element sizes. Retaining those byte
cursors and the existing patch aliases preserves MWCC allocation. A direct
linked-edge array pointer changes the object, so that rewrite is not retained.

Patch IDs encode the lower walk-group index in the low byte and the higher
index in the high byte. The separate scratch pair retains discovery order for
the two exit-group lookups. New patches start at index one; zero remains the
missing-patch sentinel. Four planes bound each patch in X/Z, while its vertical
extent spans the two linked curves. Exit adjustment moves by one twentieth of
the original endpoint difference, narrowing each updated coordinate to `s16`.
It stops when the endpoint is inside either group or reports failure after
101 unsuccessful moves. These are recovered roles, not original local names.

The checksum gate multiplies **active block indices**, modulo 2^32; it does not
hash their flag values. Block zero forces zero, block one has no effect, and
sets such as `{2,3}` and `{1,6}` collide at six. An unchanged checksum skips the
rebuild. This retail behavior is preserved rather than replaced by a better
change detector.

`tools/objfsa_patch_reset_probe.py` executes the checksum and empty-curve path
against the hash-verified EN DOL and linked source. Its 984 comparisons cover
every single active block with flag values 1 and 255, empty and combined sets,
checksum collisions and overflow, and four previous checksum values. Only map
flags and curve enumeration are mocked. Retail `memset`, the complete clear
loop, and register save/restore helpers execute. The oracle checks the whole
storage block: exactly 256 two-byte patch IDs and 181 active-group bytes clear;
other fields remain unchanged, and patch count becomes one. It also checks
neighboring bytes, stack/SDA registers, nonvolatile GPRs, FPRs, paired-single
lanes, and CR fields. Geometry and exit movement are outside this probe's scope.

The shared probe linker now accepts an entry symbol and resolves `.init`
functions as executable code, which allows this fixture to call retail
`memset` instead of linking it as an external data stub.

Source and formatting changes preserve every existing object and full objdiff
report in EN v1.0, EN revision 1, JP and PAL revision 1. The updater remains
99.49078% in EN, with three surplus pointer advances in its clear loop. No
compiler settings, split claims, or literal-pool ordering change.

```sh
python3 tools/objfsa_patch_reset_probe.py
```


## Plane-normal packing and the literal pool

`Objfsa_PackPlaneNormal` now expresses the shared conversion from a normalized
floating-point plane component to signed 16-bit storage: multiply by 32767.0f
and truncate. Both plane-construction macros call it for X and Z, giving sixteen
inlined conversions across the four walk-group and four new-patch edges. The
normalization, destination fields and plane-offset computation are unchanged.

Its ordinary static definition precedes `Objfsa_UpdateWalkGroupPatches` under
the existing GC/1.3 automatic-inlining profile. This emits the normal scale at
`.sdata2 + 0x34`, before the updater's 14.0f and 10.0f corner scales. The previous
source emitted these three floats in the order 14, 10, 32767. The full 72-byte
pool now matches retail without named scalar anchors, padding, compiler flags
or split changes. The helper's name and exact original source arrangement are
reconstructed; the pool ordering is supporting evidence, not original-source
proof.

All nineteen existing function bodies retain identical instruction bytes.
Their 228 ordered literal loads retain the same values and widths, and
non-pool relocation destinations and named data layouts are unchanged. The
helper also emits a 32-byte standalone local body; all sixteen calls inline
and no retained original function references that body. An EN diagnostic
source-link comparison confirms that the linker strips it. All named symbol
addresses and sizes and all allocated section sizes remain unchanged. Its only
text differences are ten literal-load displacements, each still loading the
same four-byte value; the only data differences are the reordered pool floats.

The complete pool and its direct r2 consumers are checked against each
configured, SHA-1-verified retail DOL. No outside direct consumer overlaps
this unit's pool:

| Version | Pool start |
| --- | --- |
| GSAE01 | `803E05C8` |
| GSAE01_rev1 | `803E1248` |
| GSAJ01 | `803E06E8` |
| GSAP01_rev1 | `803E1F90` |

The audit does not cover arbitrary materialized pointers
or indexed loads. Each verified version gains 72 matched data bytes; PAL
rev0 is excluded because the locally available DOL fails its configured hash.
All four `all_source` builds pass, and the EN strict retail checksum passes
using the retail object for this still-NonMatching unit. The remaining
patch-update code mismatch is unchanged.

```sh
python3 tools/pool_value_sequence.py src/dlls/engine/20_Hcurves/Hcurves.c --version GSAE01
python3 tools/retail_pool_audit.py src/dlls/engine/20_Hcurves/Hcurves.c --version GSAE01
```
