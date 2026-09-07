# ObjAnim root-curve phase sampling

`src/main/objanim.c` remains `NonMatching` for EN GSAE01. The current GC/1.3
build has 12 of 13 functions exact and seven floating-point operand differences
in `ObjAnim_SampleRootCurvePhase`. Its existing optimization profile is unchanged.

| Measure | Before | Current |
| --- | ---: | ---: |
| Unit fuzzy match | 99.93969% | 99.97990% |
| `ObjAnim_SampleRootCurvePhase` fuzzy match | 99.63158% | 99.87719% |
| Differing instructions | 21 | 7 |
| Integer-register differences | 14 | 0 |
| Exact functions | 12 / 13 | 12 / 13 |
| Exact data bytes | 128 / 128 | 128 / 128 |

## Confirmed source change

Declare `animDef` in the earlier pointer-local position and `state` at the end
of the declaration list. MWCC then assigns the animation definition to retail's
`r7` and the current state to `r8`, eliminating all 14 integer differences.
The executable statements, 285-instruction sequence, and 1,140-byte function
size do not change.

The object comparison changes only 16 bytes in this function. All 12 sibling
function bodies, non-text sections, named symbol layouts, and relocation records
are unchanged. The ordinary and LLDB-instrumented objects have SHA-256
`e510428cf911dd4d54d6b625df18af516e1b6dd872059fad4f1e8cac1dd7e49f`.

## Remaining floating-point allocation

The blended loop computes each curve's scaled difference between adjacent
signed-halfword samples, then combines the two differences using the move and
blend weights. Dinosaur Planet's `objGetAnimChange` in `src/objanim.c` confirms
this calculation; its blend-weight range and surrounding object layout differ,
so EN retail remains the matching authority.

The remaining differences exchange `f11` and `f12` between the integer-to-float
conversion bias and `moveDistanceDelta`. They occur at instruction indices
222, 228, 234, 236, 243, 249, and 253. In the current FPR graph, virtual 92
(conversion bias) receives `f11` at color position 32; virtual 46 (the scaled
move delta) receives `f12` at position 78. These are observed compiler IDs,
not recovered original variable identities.

Two source experiments help isolate the remaining problem:

- Giving the move samples their own cursor allows the first scaled delta to
  remain an expression temporary and produces all retail FP registers. However,
  the blend cursor's address calculation moves ahead of the move-sample loads,
  and integer allocation changes.
- Saving the first raw sample difference in the already-used `curveProgress`
  local before multiplying produces all retail registers. The blend address
  calculation then appears immediately before the first scale multiply instead
  of immediately after it. This is still a mismatch and was not retained.

Direct indexing also changes the blend loads to `lhax`. Existing root-axis
typed accesses can restore their instruction forms, but leave a different
integer-register exchange. These observations narrow the expression and cursor
lifetimes to investigate; they do not establish that clean source cannot match.

## Reproduction and validation

```sh
python3 tools/unitfuzzy.py main/objanim.c
python3 tools/strucdiff.py main/main/objanim ObjAnim_SampleRootCurvePhase
python3 tools/tricky_backend_trace.py --unit main/main/objanim \
  --function ObjAnim_SampleRootCurvePhase --graph --register-class fpr \
  --output build/flag_probe/objanim_fpr
python3 configure.py --matching
# Bound each Ninja invocation to 30 seconds.
ninja all_source
ninja
```

Both full-build checks pass. Because the TU remains `NonMatching`, the strict
checksum validates the matching build's retail fallback for this unit; it does
not claim that the seven remaining source differences are exact.
