# Callee-saved register order — measured empirically (GC/2.0, `-O4,p`)

Answers the question left open by `REGISTER_ASSIGNMENT_ORDER.md` ("web index is not a compiler
knob — what source property sets it?") and by `INVESTIGATION_web_numbering_decode.md` §8 (whose
lldb tracer has never emitted a line).

**Method: differential black-box probing, no debugger.** ~60 synthetic functions varying one
feature at a time, compiled with the project's real `mwcceppc`, each value's register read back
from a `stw`+`R_PPC_EMB_SDA21` sink pair. Harness: `tools/mwcc_re/regorder_probe.py`.

The lldb route stays blocked: `DevToolsSecurity -status` reports developer mode disabled, and
only a human with admin rights can enable it (see `INVESTIGATION_web_numbering_decode.md` §8.2).
Instrumenting wibo is also unavailable — `build/tools/wibo` is a downloaded release binary
(`config.wibo_tag = "1.1.0"`), there is no wibo source in the tree.

## The rule

Per register class (GPR and FPR are independent and never interact), the callee-saved band is
filled **top-down from r31 / f31**. Only values live across a call participate. Ordering, from
r31 downward:

1. **Ordinary locals, in reverse first-definition order.** The *last*-defined local gets r31,
   the second-to-last r30, and so on. "First definition" = the first assignment or initializer
   in statement order.
2. **Compiler temps**, below every ordinary local. Earlier-referenced temps take the higher
   register; an inner loop's temp sits below its outer loop's.
3. **Unmodified parameters**, below everything else, with the *last* parameter highest.
   ⚠️ **CONTRADICTED (w59, measured on `dll_2E_func07`).** This rule predicts bottom-up `obj<seq<s<a<b`; retail is **`a<b<obj<seq<s`** — the NARROW (`s16`) params are *lowest*, forming their own sub-band BELOW the wide params, and they already match ours. Treat rule 3 as unverified.
   ⚠️ **Also unresolved by this model:** in `dll_2E_func07` retail's local `player` **dies FIRST yet takes the HIGHEST register (r31)**, which refutes death-point ordering directly. Five candidate priority keys (first-reference, last-reference, reference count, loop-weighted references, live-range length) all sit at base rate over ~60k pairs; loop-weighted frequency is *below* chance (44.74%), killing 'hottest variable wins r31'. **No global per-variable priority sort exists.**

### Declaration order is inert

> ⚠️⚠️ **REFUTED (w59, freshly-rebuilt probe — this section is WRONG and `CLAUDE.md` line 84 is CORRECT).**
> Using this file's own `scratchpad_L51` probes, rebuilt from source to rule out stale objects, with
> **five** int locals all live across a call and the **assignment order held identical (a,b,c,d,e)**:
> * `p1c` — declared `int a,b,c,d,e;` → `a→r31, b→r30, c→r29, d→r28, e→r27`
> * `p1b` — declared `int e,d,c,b,a;` → `a→r27, b→r28, c→r29, d→r30, e→r31`
>
> The band **fully inverts** with only the declaration order changed. **Declaration order is the
> lever; first-assignment position is not sufficient.** The 3-local counter-probe below does not
> generalise — declaration order only moves a local *relative to other eligible band-2 locals*, so with
> ≤1 eligible local it is provably inert, which is what that probe and the `dll_2E_func07` observation
> actually measured. **Screen by counting eligible band-2 locals before concluding inertness.**


This is the headline correction. `CLAUDE.md` says "Local **declaration order** sets saved-register
homes … Reorder decls to swap registers." That is wrong as stated — reordering declarations
changes nothing. It *appeared* to work only because moving a `T x = expr;` declaration also moves
its initializer, i.e. its first definition.

Proof, synthetic (`decl_rev_def_fwd` vs `decl_eq_def`): declaring `int c; int b; int a;` and
defining `a,b,c` gives the same `a=r29 b=r30 c=r31` as declaring in `a,b,c` order.

Proof, real code: permuting the three uninitialized declarations in
`drshackle_updateSwingBlend` (`int hitResult; int yawDelta; f32 fade;` → reversed) produces a
**byte-identical** object file (md5 `042323eeaf0e1298298d60ca27082655` both ways).

**The lever is the first assignment, not the declaration.** To permute saved registers, split
`T x = expr;` into `T x;` plus a relocated `x = expr;`, or reorder the initializing statements.

## What counts as a "compiler temp" (band 2)

These wrap below the ordinary locals even though they are named source locals:

| Shape | Case |
|---|---|
| Loop accumulator (`c += g(i)` with `c` defined before the loop) | `loop_accumulator` |
| Induction variable | consumes a register in the same band |
| A def before a branch plus a def inside it (a real phi) | `phi_if`, `phi_switch` |
| `s16` local needing a conversion temp (`u8` does not) | `narrow_s16` |

A def that only reaches a join from *exclusive* arms is **not** a phi in this sense — such a
local numbers normally, at the position of the `if` statement. A straight-line redefinition
(`c = f2(); barrier(); c = g(c);`) is also normal.

## Eligibility

- **Address-taken** locals leave the band entirely (stack; `addr_taken`).
- **Dead** locals are ignored; adding one does not shift anything (`dead_local`).
- **Pure aliases coalesce and cost nothing**: `int sz = p;` shares the parameter's register
  (`pure_alias` — `sz` and `p` are both r29), and `T* s = (T*)param;` likewise. This is why
  swapping the two aliased pointer declarations at the top of `drshackle_updateSwingBlend`
  is also byte-neutral.
- **A cast across classes does not coalesce**: `int oid = (int)o;` consumes its own register at
  its definition position (`cast_alias`).

## Validation

**Retail ground truth — `MagicPlant_free`** (`build/GSAE01/obj/main/dll/dll_00FE_magicplant.o`).
Source has params `obj`, `freeChildren` and locals `plant` (a pure alias of `obj`), `state`.
Rule predicts: `state` is the only ordinary local → r31; then params, last-highest →
`freeChildren` r30, `obj` r29. Retail emits exactly `mr r29,r3` / `mr r30,r4` /
`lwz r31,184(r29)`. This also explains the recorded regression: adding `int objId = (int)obj;`
inserts a non-coalescing web *below* `state`, shifting the whole band.

**Blind predictions.** Two cases were predicted before compiling and both were exact:

- 1 param + 3 locals defined in order `z, x, y` → predicted `y=r31, x=r30, z=r29, q=r28`. Correct.
- 2 params + 2 locals + 1 loop accumulator + 1 IV → predicted locals `b=r31, a=r30`, accumulator
  r29, IV r28, params `q=r27, p=r26`. Correct.

Every one of the ~60 probes is consistent with the rule; no counterexample was found.

## Reconciliation with the static decode

`INVESTIGATION_web_numbering_decode.md` derived, statically, "band 2 = eligible locals in REVERSE
DECL order". The measurements agree on everything except the order key: it is reverse
*first-definition* order, not reverse declaration order. The most likely mechanism is that
CFunc.c appends a local to the `0x5e9b00` list when the object is first *processed as a
definition*, not at its declarator. That §4 claim was explicitly tagged as the model's weakest
link; this supersedes it. Higher web index still maps to lower register number, as decoded.

## Using this

`tools/mwcc_re/regorder_probe.py` runs the case library, or takes `--file` for a new probe. Add
a case whenever a function's banding is not explained here — a probe costs about a second and
does not need the debugger, so an unexplained permutation should be turned into a probe rather
than guessed at.
