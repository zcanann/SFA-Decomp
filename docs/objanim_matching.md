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

## Frontend and allocator follow-up

A second investigation leaves the source and match percentage unchanged.
`mwcc_frontend_trace.py` exposes the distinction between the two closest
expressions through all 73 captured frontend stages:

- The current shared sample cursor keeps the complete move product assigned
  to the named `moveDistanceDelta` local. The blend product is substituted
  into the final weighted sum.
- Staging the raw move-sample difference creates an anonymous frontend local
  for that difference. The scale multiply is then substituted into the final
  sum, after the separate blend-cursor assignment. This explains the otherwise
  exact variant's one misplaced address calculation.
- Direct typed blend accesses let the move product become an expression
  temporary and reproduce the retail FP registers and instruction order.
  Their shared blend address becomes a backend temporary, exchanging `r8`
  and `r9` at ten integer operands. This variant is also not retained.

The allocator tracer now captures and replays FPR simplification, as well as
physical coloring and operand rewriting. The GC/1.3 executable establishes
the policy without changing compiler behavior:

| Compiler location | Observed role |
| --- | --- |
| VA `0x4FCB70` | Counts unblocked registers using the active class's physical count and mask |
| VA `0x506D58` | Copies the active class's original virtual-register count into the shared cutoff at `0x5DD948` |
| VA `0x507070` | Simplifies either register class using those inputs |
| VA `0x50712C`, `0x507164` | Compare candidates against that same cutoff during high-degree selection |

The live ObjAnim FPR capture has 32 available registers and cutoff 116. Replay
reproduces the entire simplification order and all 84 physical-color choices,
with zero high-degree removals. The corresponding GPR capture reproduces all
115 choices. Both ordinary/instrumented objects retain the hash above.
An independent `playerState25` FPR capture also reproduces simplification and
all 105 color choices, with zero retail differences and unchanged instrumented
output. These captures validate the allocator model; they do not establish
the original ObjAnim expression spelling.

Legacy traces still load. Reports explicitly distinguish an unreplayed legacy
FPR simplification from a verified replay with zero high-degree removals.
Storage, precision, cursor-type, and inline-helper experiments did not improve
the current source. Further work should target an expression temporary for the
complete move product while preserving the retail blend-address ordering and
integer allocation.

## Reduced expression-order case

`tools/objanim_expression_order.py` builds the isolated kernel in
`tools/fixtures/objanim_expression_order.c` with the configured ObjAnim compiler
command. This is a compiler reproducer, not proposed retail source. A
straight-line pair of curve calculations does not reproduce the problem.
Keeping the sample-index wrap, reused cursor, and earlier progress use produces
the same tradeoff in 104 instructions, without animation objects or headers:

| Variant | Conversion bias | Move product | Multiply index | Blend address index |
| --- | --- | --- | ---: | ---: |
| Named product | `f11` | `f12` | 57 | 58 |
| Staged raw difference | `f12` | `f11` | 58 | 57 |

The new `mwcc_frontend_trace.py --propagation` option records the decisive
first-pass events. In the named kernel, assigning the blend cursor at frontend
node 145 invalidates the available move-product expression from node 135.
In the staged kernel, that assignment instead invalidates the raw-difference
expression (132 at 150); the move-product expression from 140 is substituted
at use 176. The full game function shows the same named-product invalidation
at nodes 765 and 775. These are observed node IDs within the captured pass,
not source symbols or stable compiler-wide identifiers.

This establishes the dependency that blocks propagation, rather than merely
observing the resulting allocator order. The hooks cover the expression
replacement at VA `0x46F182`, destination invalidation at `0x46F26B`, and
dependency invalidation at `0x46F2FB`. Events retain `available_before` because
clearing an already-unavailable candidate is not a new invalidation.
`after_stage` indexes the preceding entry in `stages.json`; node IDs must be
interpreted against that pass's listing. The event file is hashed in the trace
manifest, and the ordinary/instrumented object identity gate still applies.

Both reduced cases reproduce their instruction order under instrumentation;
the full function retains its existing object hash. Inline helpers, scoped
constant locals, and preserving/reusing scale inputs did not close the gap.
No new game-source spelling was retained. The source match remains 99.97990%.

```sh
python3 tools/objanim_expression_order.py --trace
python3 tools/mwcc_frontend_trace.py --unit main/main/objanim \
  --function ObjAnim_SampleRootCurvePhase --propagation \
  --output build/flag_probe/objanim_propagation
python3 -m unittest discover -s tools -p 'test_mwcc_frontend_trace.py'
```

## Reproduction and validation

```sh
python3 tools/unitfuzzy.py main/objanim.c
python3 tools/strucdiff.py main/main/objanim ObjAnim_SampleRootCurvePhase
python3 tools/tricky_backend_trace.py --unit main/main/objanim \
  --function ObjAnim_SampleRootCurvePhase --graph --register-class fpr \
  --output build/flag_probe/objanim_fpr
python3 tools/mwcc_frontend_trace.py --unit main/main/objanim \
  --function ObjAnim_SampleRootCurvePhase \
  --output build/flag_probe/objanim_frontend
python3 -m unittest discover -s tools -p 'test_tricky_backend*.py'
python3 configure.py --matching
# Bound each Ninja invocation to 30 seconds.
ninja all_source
ninja
```

Both full-build checks pass. Because the TU remains `NonMatching`, the strict
checksum validates the matching build's retail fallback for this unit; it does
not claim that the seven remaining source differences are exact.

## Cross-architecture and register-role comparison (2026-09-07)

The sibling `../dinosaur-planet` checkout supplies both reconstructed C and the
ROM-backed MIPS assembly for `objGetAnimChange`. The 270 annotated instruction
words in `asm/objanim.s` were checked against their file offsets in
`baserom.z64`; all agree. The function occupies `0x8002493C..0x80024D74`
(exclusive end), and its 1,080 instruction bytes have SHA-256
`35087f98f06f518373a8b2481c3281e2093d7ee2b511855e7f30a4a3dd35fdbb`.
The C contains explicitly marked matching artifacts and is not original source.

| Operation | Dinosaur Planet ROM | SFA EN retail |
| --- | --- | --- |
| Function size | 270 instructions, 1,080 bytes | 285 instructions, 1,140 bytes |
| Blend-weight denominator | 1023.0f | 16384.0f |
| Signed sample conversion | `lh`, `mtc1`, `cvt.s.w` | `lha`, `xoris`, stack word stores, `lfd`, `fsubs` |
| Loop addressing | Carries a move-sample pointer and byte offset, advances both by two, resets on wrap | Recomputes the doubled index and move address after wrap handling |
| Blended delta | Two sample differences, separate scale/weight multiplies and additions | Same two differences; contracts one weighted multiply/add into `fmadds` |
| Instruction order | Interleaves blend loads with move conversion/multiply | Completes the move product before calculating the blend address |

Both binaries support the same cumulative-distance search and signed sample
interpretation. Their address induction, scheduling, floating-point contraction,
ABI and object layouts differ. The MIPS register names and load scheduling do
not establish the GC source cursor lifetimes, and importing its arithmetic
spelling does not solve the match.

### Closed mapped interference graphs

New LLDB captures independently reproduce the baseline object hash above.
A second source override replaces only the blended loop's cursor reassignment
and blend calculation with the following header-relative access:

```c
blendDistanceDelta = blendScale *
    ((f32)((ObjAnimRootCurveAxis*)(blendSamples - 1))->samples[sampleIndex + 1] -
     ((ObjAnimRootCurveAxis*)(blendSamples - 1))->samples[sampleIndex]);
```

This is a diagnostic variant, not a retained source change. `blendSamples`
already points past the selected axis's presence marker; subtracting one
halfword recovers its header. Unlike a cast at `blendSamples` itself, this
spelling emits the retail `add`/`lha` sequence. It has all retail FP operands
and ten GPR operand differences. Its instrumented and ordinary objects share
SHA-256 `f90b5a41153858e08cdaf30399eede248a0fea7a0fb55d86c904f5d7fd83c9a8`.

`tools/mwcc_register_compare.py` follows emitted instruction records back to
pre-rewrite virtual operands, checks whether their correspondence is one-to-one,
and compares the captured interference edges under that correspondence. It
first reuses the object-hash, IR/ELF alignment, simplification and physical-color
replay checks. It requires equal opcode streams; it does not prove semantic
equivalence or compare different architectures.

| Class | Mapped nodes, including fixed registers | Partition conflicts | Mapped edge differences | Unmapped neighboring nodes |
| --- | ---: | ---: | ---: | ---: |
| GPR | 122 | 0 | 0 | 0 |
| FPR | 105 | 0 | 0 | 0 |

Thus the mapped graphs are closed and have identical interference, despite
different virtual numbering and physical choices. The exact changed roles are:

| Role | Baseline virtual / physical | Typed-view virtual / physical |
| --- | --- | --- |
| Move product | 46 / f12 | 98 / f11 |
| FP conversion bias | 92 / f11 | 91 / f12 |
| Blend address | 47 / r9 | 133 / r8 |
| Doubled sample index | 126 / r9 | 125 / r8 |
| Integer conversion high word | 129 / r8 | 128 / r9 |

The address mismatch is not a spill or increased register pressure. The desired
FP result comes with promoting the named move product to an expression temporary;
the unwanted GPR result comes with promoting the named blend address to an
expression temporary. Both captures replay with zero high-degree removals. This
separates numbering/order sensitivity from changed interference, rather than
inferring it solely from similar assembly. A source spelling that retains the
named blend address also has to preserve its position after the move multiply;
the tested separate-cursor and inline-helper variants still move it earlier.

The local captures and comparison JSON are under `build/objanim_lldb/`. Given
fresh baseline and typed-view captures of each register class, reproduce the
comparison with:

```sh
python3 tools/mwcc_register_compare.py \
  build/objanim_lldb/gpr/trace.json build/objanim_lldb/typed_gpr/trace.json \
  --function ObjAnim_SampleRootCurvePhase
python3 tools/mwcc_register_compare.py \
  build/objanim_lldb/fpr/trace.json build/objanim_lldb/typed_fpr/trace.json \
  --function ObjAnim_SampleRootCurvePhase
python3 -m unittest discover -s tools -p 'test_mwcc_register_compare.py'
```

No tested source variant improves the existing objdiff score. The TU remains
`NonMatching`, 99.97990% fuzzy, with 12/13 functions and all data exact.


### Addressed product store (2026-09-08)

The reduced reproducer now also tests replacing the move-product assignment
with `*(f32*)&moveDistanceDelta = ...`. This is a diagnostic lvalue spelling,
not proposed game source. It produces both the desired FP registers and the
multiply-before-address order, but retains an extra `stfs` between them.

| Reduced variant | Instructions | Bias / product | Product index | Blend address index | Intervening store |
| --- | ---: | --- | ---: | ---: | --- |
| Named product | 104 | f11 / f12 | 57 | 58 | none |
| Staged difference | 104 | f12 / f11 | 58 | 57 | none |
| Address-cast store | 105 | f12 / f11 | 57 | 59 | stfs at 58 |

All three ordinary/instrumented object hashes agree under frontend tracing.
The address-cast reduced object has SHA-256
`6e4e762417a7ade3e31df36ca6e2723280b0334c721e7a8c82afb9aa7b13b8be`.
Its full-function counterpart similarly adds one instruction and shifts stack
spill offsets. An inline output-parameter helper reproduces this only when its
store also contains the cast: plain `*out = ...`, direct address dereferencing,
and scalarized struct outputs return to the original seven-register mismatch.
Thus taking an output parameter alone does not explain the change.

In the final full-function frontend listing, the ordinary assignment addresses
the local directly through `EINDIRECT`; the casted store inserts `ETYPCON`
between the local operand and `EINDIRECT`. The latter still forwards the product
into its eventual arithmetic use but retains the memory store. Explicit
`deadstore`, `deadcode`, and `cse` diagnostic options did not remove that store;
production compiler flags remain unchanged. Unrolled two-curve loops and
aggregate returns likewise introduced stores or extra rounding instructions.

Reproduce all three reduced cases with
`python3 tools/objanim_expression_order.py --trace`. The JSON report records
product-store indices as well as register and instruction-order observations.
These results distinguish another frontend path but do not improve the TU's
99.97990% score or establish an exact source spelling.
