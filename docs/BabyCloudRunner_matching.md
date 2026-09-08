# Baby CloudRunner (DLL 332) matching

DLL 332 fully matches EN GSAE01 and links from C with the common GC/1.3 compiler
and `cflags_dll_noopt`. All 14 retail functions (4,428 bytes) and all 236 data
bytes are exact, including the complete 68-byte `.sdata2` pool.

The reconstruction uses four private helpers whose automatic inlining preserves
every retail instruction. Their out-of-line copies account for literals emitted
before their surviving loaders:

| Helper | Operation | First emitted literals |
| --- | --- | --- |
| `babyCloudRunner_startMove` | Restart an animation at its beginning | `0.0f` |
| `babyCloudRunner_canCapture` | Test range, freed state, and player interaction eligibility | Signed integer-conversion bias |
| `babyCloudRunner_renderModel` | Render the model and hit volumes at normal scale | `1.0f` |
| `babyCloudRunner_followCurve` | Update curve velocity, orient the object, and move it | `10.0f` |

The curve helper accepts the path advance step, movement speed, and pitch factor.
Its caller supplies `5.0f * state->curveSpeed` and `0.2f` for the latter two
parameters. The helper retains the arrival radius of ten advance steps and the
roll factor of ten. These roles follow the implementations of
`Obj_UpdateRomCurveFollowVelocity` and `Obj_SmoothTurnAnglesTowardVelocity`.
Keeping those caller tunables separate reproduces their later pool positions.

All nine calls inline. The linker strips all four out-of-line helper copies and
retains their shared literal pool. No additional data definitions or compiler
profile changes are required. The helper names and decomposition are inferred
from the existing EN operations and pool order; the emitted result is validated
against retail.

Local declaration order matters in the capture helper and its descriptor caller.
GC/1.3 backend captures through LLDB reproduced ordinary object hashes; extraction
initially swapped the capture-result and state registers in the two prompt paths.
Declaring the state before the result recovers the original register allocation.
The generic-pointer assignment in `tryCapture` is retained.

Validation covers raw retail instruction bytes, literal-load value sequences,
all data sections, helper stripping, and the link input selecting the compiled
332 object. `python3 configure.py --matching`, `ninja all_source`, and strict
`ninja` pass with `main.dol: OK`. Formatting is checked separately and must
preserve the complete raw object hash.
