# Game math literal-pool recovery

## September 6: Three complete pools under GC/1.3

The following units now use ordinary typed numeric literals instead of late
`extern const` definitions. MWCC emits their complete retail constant pools
without section attributes, synthetic arrays or extra definitions.

| Unit | Functions | Exact pool bytes | Code fuzzy, unchanged |
| --- | ---: | ---: | ---: |
| `main/math_8029312c` | 3 | 12 | 81.63636% |
| `main/trig_float_helpers` | 4 | 80 | 59.221153% |
| `dolphin/MSL_C/PPCEABI/bare/H/math_80293da4` | 7 | 184 | 83.05306% |

Thirty-six named scalar definitions and their forward declarations are removed.
Float suffixes and double precision are preserved. The reciprocal helper's
external `sFastReciprocalTwo` is not part of the angle-vector pool and remains
external. No removed definition has a source consumer outside its owning TU.

The angle-vector polynomials use a consistent Horner form with `angleSquared`
on the left of each nested product. Substitution alone reversed two functions'
multiply-add operands; this source form preserves their original instructions
while retaining the exact pool. Evaluation still follows the same polynomial
degrees, intermediate precision and fused operations.

All 14 function byte sequences are identical to the preceding source objects.
An isolated rebuild of the preceding sources reproduces their recorded SHA-256
hashes. Auditing all relocations verifies 159 local floating-point loads retain
their exact four- or eight-byte payloads; other relocation records are unchanged.
The new pools have exactly the retail sizes, eight-byte alignment and contents.
MWCC marks its `.sdata2` object section writable while the extracted retail
object does not; this is not a claim of identical ELF metadata or complete TUs.

Objdiff now credits 276 additional data bytes. Code, compiler versions, compiler
flags, matching classifications, splits and active-target symbols are unchanged.
The units remain `NonMatching`: the strict DOL gate links their retail objects,
so it supplements rather than replaces the source-object comparison.

## Remaining evidence

The square-root arithmetic already agrees instruction-for-instruction with
retail apart from its prologue and epilogue. GC/1.3 emits paired-single saves
and restores absent from retail. Changing only `-proc gekko` to `-proc 750`
does not remove them; that ineffective flag experiment is not retained.

Literal-only probes of `trig`, `acosf`, `sincosf` and `math_8029454c` emit pools
in different orders from retail. None is landed here. `math_float_helpers`
also takes addresses of some named scalars, so a blanket literal substitution
does not compile. Those uses require source recovery beyond this substitution.

Local probes and relocation audits are under `build/flag_probe/`:
`math_literal_pool_probe.py`, `angle_vec_literal_probe.py` and
`math_literal_pool_audit.py`. The baseline audit uses `git show HEAD:<source>`;
pin it to the pre-change revision when rerunning after this checkpoint.
