# Joint-matrix function boundaries and Dinosaur Planet comparison

Investigation: 2026-09-06, SFA EN v1.0, starting at `2ef1617d0c`.

`modelAnimBuildJointMatrices` occupies `0x80006C6C..0x80007F78` (0x130C /
4,876 bytes) in `main/render.c`. Its internal calls, shared state and outer
epilogue form one region. There is no evidence here of a coroutine scheduler
or resumable C language construct. The original source language remains
unresolved: authored assembly, assembly macros, mixed C/assembly and unusual
compiler output have not been conclusively distinguished.

## Dinosaur Planet supplies the corresponding implementation

The sibling `../dinosaur-planet` checkout at
`c4340802dc9f62e1181d00cc34c3175fca6ca4be` has the corresponding entry at
`func_8001B4F0`, in generated `asm/model_asm.s`. The association is supported
by the same eight-argument caller shape in `src/model.c`, the animation-state
offsets `0x2C`, `0x34`, `0x4C`, `0x58` and their second-channel counterparts,
mode bits `1`, `2`, `0x40`, and the complete nine-call sequence through four
internal helpers. It is substantially closer than the JFG reference.

| SFA EN | Dinosaur Planet | Correspondence |
| --- | --- | --- |
| `0x80006C6C` | `0x8001B4F0` | Outer animation/matrix entry |
| `0x80006E34` | `0x8001B6F0` | Blend and transform helper; preserves return address in a GPR |
| `0x800072C4` | `0x8001BC00` | Rotation helper called twice by the preceding helper |
| `0x800074EC` | `0x8001BCF0` | Interpolated packed animation decode |
| `0x80007738` | `0x8001BF70` | Alternate packed animation decode |
| `0x80007F1C` | `0x8001C83C` | Shared outer epilogue |

At DP `0x8001B6F4`, `$ra` is copied to `$t9`; the helper calls
`func_8001BC00`, then returns through `$t9` at `0x8001BA28`. SFA saves LR
in `r29` at `0x80006E34`, calls `0x800072C4`, and restores LR from `r29` at
`0x80007134`. The outer function's continuation occurs after the internal
helper bodies on both platforms. These are observed binary facts, independent
of any compiler attribution.

DP's project-wide `compiler: IDO` is **not evidence that this function has been
reproduced with IDO**. Its `splat.yaml` classifies the `0x1C0F0` ROM segment as
`asm, model_asm`; both actual and expected `model_asm.o` are assembled from
the same generated disassembly. There is no recovered C body to compare.
The split `asm` classification is also not proof of original handwritten source.
See the upstream [prototype](https://github.com/zestydevy/dinosaur-planet/blob/master/include/sys/gfx/model_asm.h),
[callers](https://github.com/zestydevy/dinosaur-planet/blob/master/src/model.c),
and [split configuration](https://github.com/zestydevy/dinosaur-planet/blob/master/splat.yaml).

JFG at `8c94f513822c9647605b71bce908b1126b375a67` keeps related animation code
in tracked [`src/hasm/gen_anim_data.s`](https://github.com/Ryan-Myers/Jet-Force-Gemini/blob/master/src/hasm/gen_anim_data.s),
including a shared outer epilogue after helper entries. This is a useful
representation precedent and a weaker lineage comparison, not an IDO match.

SFA additionally has paired-single operations, polynomial trigonometry in
the rotation helper where DP uses table lookups, and frames of `0xFC` and
`0x34` bytes. Those differences preclude treating the two implementations
as identical compiler input/output. Private calling conventions and unusual
stack alignment support investigating assembly lineage, without establishing
it. See also [the zlb provenance audit](zlb_provenance.md). The retail
`source_leaks.py --search render gen_anim model` search found no source clue.

## DTK failure and prototype

Stock DTK **1.8.0 and 1.8.3** both reject changing the entry from `type:label`
to `type:function size:0x130C`:

```text
Found multiple functions inside a symbol: 3:0x80006C6C and 3:0x800072C4.
```

`FunctionSlices::check_prologue` treats the second internal prologue as a
bad function extent. Simply upgrading does not fix it. Another project,
[Crash Tag Team Racing, reported the same diagnostic](https://github.com/encounter/decomp-toolkit/issues/111);
that does not imply the same cause. Upstream's
[`skip_cfa_ranges`](https://github.com/encounter/decomp-toolkit/commit/d766ff50ca96b803f4f8a26991387a7dffdbe6cc)
deliberately still analyzes explicitly defined function symbols, so it does
not provide the required named-function target.

`tools/patches/dtk-nocfa.patch` adds an explicit, per-symbol **experimental**
`nocfa` attribute to DTK v1.8.3 (`e4219e7644fb7b96d920d5bc3d1d950f5569dcaf`):

```text
modelAnimBuildJointMatrices = .text:0x80006C6C; // type:function size:0x130C nocfa
```

This trusts the supplied function extent rather than analyzing its prologues.
It requires an explicit nonzero, instruction-aligned size inside a code section.
The normal checks for other functions, symbol/split overlaps and final binary
checksum remain. Relocation analysis still runs, including internal `bl`
references to the containing function plus an addend. `nocfa` survives symbol
merging and writing `symbols.txt`.

This is an escape hatch for independently established boundaries, **not automatic
recognition of arbitrary nested functions**, nor a fix to every private-ABI dataflow
case. It can hide an incorrect boundary within its annotated range; review the
retail control flow before applying it elsewhere. The patch is local and has not
been submitted to upstream DTK.

## Reproduce and use

Requires Git and a Rust toolchain capable of building upstream DTK v1.8.3.
The helper fetches the exact revision, applies the checked-in patch and builds
with the upstream lockfile. A patch-specific cache prevents reuse of a stale
binary; it refuses to overwrite a modified cached checkout.

```sh
python3 tools/dtk_nocfa.py --test
python3 configure.py --matching --joint-matrices-nocfa
# Run each ninja invocation with the project's normal 30-second timeout.
ninja all_source
ninja
```

Select `main/render` in objdiff. Its target now contains the named function,
including its 4,876 bytes, instead of `gap_03_80006C6C_text`. All helpers stay
in the existing render TU. The generated config and symbols live under
`build/GSAE01/joint-matrices-nocfa/`; canonical target config is unchanged.
DTK's enrichments of this generated symbol file survive configure reruns,
and changes to the canonical inputs refresh the overlay.

Return to the upstream tool and normal configuration with:

```sh
python3 configure.py --matching
ninja all_source
ninja
```

The analyzer experiment does not mark `render.c` matching. The subsequent C
recovery described below supplies the implementation for this named target.
Finding an IDO-generated C counterpart would require recovering a C body and
comparing its emitted MIPS code; the generated DP assembly alone cannot
establish that.

## Validation

- Stock 1.8.0 and 1.8.3 both reproduce the prologue error with explicit bounds.
- Patched DTK splits the full EN DOL successfully and emits one `STT_FUNC`
  named `modelAnimBuildJointMatrices`, size `0x130C`.
- Three synthetic DTK regression tests cover the original failure without the
  annotation, preserved bounds/neighbor analysis/relocations/symbol round-trip,
  and rejected malformed annotations. All seven upstream-plus-added tests pass.
- Three Python tests cover overlay persistence, canonical input refresh and
  refusal to reuse a changed function anchor.
- `ninja all_source` and the strict matching link both pass in the experimental
  configuration. Linked SHA-1: `e750e8e894707a52446118a4b84f1b58b677b269`.
- Objdiff reports the named function as **unmatched**, size 4,876. Total measured
  code increases by 4,876 bytes and one function; matched code stays at 2,339,816
  bytes. This is improved accounting and an available matching target, not a C
  matching gain.
- A second `ninja all_source` is clean (`no work to do`). Default configuration
  also passes both build gates.

## First C matching attempt

`src/main/render.c` now implements the complete entry in ordinary C, within the
existing TU and under its existing GC/1.3 settings. The private helpers decode
packed frame pairs, evaluate the retail sine/cosine polynomials, blend
quaternions and scale/translation components, construct local matrices, and
apply the joint hierarchy. No inline assembly, compiler exception or split
change was added.

The recovered 64-byte work-slot union makes the storage reuse explicit:
rotation pairs begin at `+0x1C`, scale pairs at `+0x28`, and translation pairs
at `+0x34`. Cached quaternions occupy `+0x00` and `+0x10`; the matrix view
overwrites these fields in later passes. Adjustment records use separate
offsets for the two animation channels and a `0x1000` terminator. The paired
decoder keeps flag bits in constant scale words, whereas the interpolated
decoder masks them out.

Two unusual retail paths are preserved:

- The blended matrix's zero-X-scale path at `0x800071FC` writes its first
  column across the first row; later column stores overwrite two of those
  writes. Zero scales ordinarily become 1024 during blending, but the store
  path itself is retained.
- If the last joint is masked, the blend loop branches to the shared outer
  epilogue instead of returning to its internal caller. In mode `0x40`, this
  ends the first cache pass before decoding or blending the second animation.
  Expanding the execution probe to masked final joints exposed this difference
  in the first C draft.

Final objdiff similarity for the function is **15.515177%**, compared with a
missing source body before this attempt. The first separate-helper draft was
8.708777%; ordinary `static inline` choices improved it, but inlining every
stage reduced the score. The correctly preserved early return lowered an
intermediate 16.893354% result. These are fuzzy instruction comparisons, not
percentages of verified functionality. The nine already-exact functions and
all existing data matches in `render.c` retain their previous results. No
additional bytes are yet counted as exactly matched.

The remaining codegen gap is substantial: MWCC emits normal helper boundaries,
integer/float conversions and scalar matrix arithmetic, while retail has
internal private calling conventions, quantized loads/stores and paired-single
matrix arithmetic. This attempt does not prove which language produced retail.
`render.c` remains `NonMatching`.

### Execution probe

`tools/joint_matrices_emulation_probe.py` links the compiled render object into
an isolated test ELF and executes both that code and the original EN DOL with
Unicorn. A small instruction hook implements the retail Gekko paired-single
subset, including GQR3/GQR5 conversions. The probe needs Python 3.13+ and the
optional `unicorn` package; it does not affect normal build dependencies.

```sh
python3 -m venv build/joint-matrices-probe-venv
build/joint-matrices-probe-venv/bin/pip install unicorn==2.1.4
build/joint-matrices-probe-venv/bin/python tools/joint_matrices_emulation_probe.py
```

The default 228 synthetic comparisons cover constant and variable-width
streams, fields crossing loaded-word boundaries, fractional and saturated
phases, angle wrapping, scale/translation adjustments, extrapolated blend
weights, cached quaternion inputs/outputs, root rotation overrides, remapped
joints, skipped joints and branched hierarchies. Packed output words compare
exactly; matrix/quaternion floats use relative and absolute tolerances of
`2e-5`. The probe also checks return, stack restoration, nonvolatile GPR/FPR
restoration and output guards. All 228 pass.

Coverage reaches 1,212 of 1,219 retail instructions. The seven unvisited
instructions are the branch at `0x80006E30`, after a helper path that exits via
the outer epilogue, and three two-instruction `0x8000` quadrant cases in the
half-angle helper. A signed 16-bit angle shifted right once cannot select that
quadrant. Coverage is useful evidence, not a proof for arbitrary inputs. This
software probe does not establish bit-exact Gekko floating-point behavior or
in-game correctness; hardware rounding/denormal behavior and the remaining
instruction mismatches still need investigation.

Generated results and the test ELF go under `build/joint-matrices-emulation/`.
Both default and experimental configurations pass `ninja all_source` and a
fresh strict checksum check after this recovery; the retail DOL SHA-1 remains
`e750e8e894707a52446118a4b84f1b58b677b269`.
