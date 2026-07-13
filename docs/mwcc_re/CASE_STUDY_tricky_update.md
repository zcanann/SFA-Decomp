# Case study: `Tricky_update` and full-TU register webs (GC/2.0)

Status: **validated in the real TU** against GSAE01 on 2026-07-13. The final
`dll_00C4_tricky` report was 100% (23472/23472 code bytes, 324/324 data bytes,
33/33 functions); `Tricky_update` itself was 8672 bytes at 100%. The matching
changes are in `e4f97347b4`, `a9d9cf86ca`, and `0bbf9bf3e7`.

This is a case study, not a list of universal MWCC laws. Each source spelling
below is evidence that a shape is reachable in this TU. It should still be
tested in the destination TU; preceding functions and byte-neutral spellings
can change compiler state (see `INVESTIGATION_cross_function_state.md`).

## What made the last mismatches difficult

The remaining instructions already expressed the right behavior. The misses
were almost entirely:

- which live range received a volatile or saved register;
- whether a zero definition was reused or rematerialized;
- which expression owned an address calculation;
- which literal-pool symbol a byte-identical load relocated against.

Reconstructing stranger control flow did not help. Normal `for` loops, scoped
locals, a direct callback-table access, and ordinary compound assignments were
enough once their lifetimes matched the target.

## Findings

### 1. Test the whole translation unit, even when scoring one function

`Tricky_update` was permuted from a full-TU context with
`PERMUTER_FUNC=Tricky_update`, so the score covered one function while MWCC still
saw all preceding declarations and functions. Isolated snippets were useful for
showing that a shape was possible, but were not authoritative.

Useful checks were:

```sh
python3 tools/ndiff.py main/dll/dll_00C4_tricky.c Tricky_update
python3 tools/function_objdump.py main/dll/dll_00C4_tricky.c Tricky_update --diff
```

A full-TU permuter search found the exact callback-table expression after local
experiments had stalled. The winning mutation was then rewritten cleanly in the
real source and revalidated there.

### 2. Expression ownership can change address association

These two callback-table spellings are semantically equivalent, but did not
produce the same address web:

```c
handlerBase = table->handlers;
handlerBase[stateIndex](obj, state);
```

```c
((TrickyHandlerFn*)(base + 0x24))[stateIndex](obj, state);
```

The direct byte-offset form produced the target `slwi` / base `add` / indexed
`lwz` association. A padded containing struct and a separately cached handler
base associated the addition differently. The final spelling is also plausible
for code accessing an interface or table embedded at a known runtime offset.

Practical lever: when all instructions exist but an `addi`/`add` is tied to the
wrong live range, vary which expression owns the offset. Test a typed containing
object, an array pointer at `base + offset`, and a separately cached subobject;
none is universally preferred.

### 3. Block scope and declaration order are register-allocation inputs

The late voice-event loop matched after its cursor and secondary sound ID became
block-scoped locals, declared in target-compatible order:

```c
if (talking != 0)
{
    u8* soundCursor;
    int sfx2;

    soundCursor = (u8*)state + 0x80c;
    sfx2 = 0;
    /* ... */
}
```

Reusing a function-scope cursor extended or joined a web that the target kept
separate. Moving both locals into the smallest natural block restored the target
volatile-register choices without casts or dummy operations.

Practical lever: if a mismatch starts at a late local's first definition and
then follows only that value, try its natural block scope and swap adjacent
declaration order. Do not globally rescope every local; this changes the whole
interference graph.

### 4. A small aggregate can preserve a source-level lifetime boundary

The flame-child cleanup needed its zero initialization to remain in the same
target register web as the loop counter. A plain scalar produced one extra
`li 0`; chained assignments, direct literals, and a separate scalar declaration
did not remove it. An `u8` counter removed that difference but introduced
`clrlwi`/unsigned-compare instructions.

The exact clean-C form used a local aggregate:

```c
struct
{
    int index;
} childLoop;

childLoop.index = 0;
state->followPhase = childLoop.index;
for (; childLoop.index < 7; childCursor += 4, childLoop.index++)
{
    /* ... */
}
```

This kept a distinct source object long enough for MWCC's propagation/value
numbering path to produce the target zero web. The loop itself remained a normal
`for` loop. One-member aggregates are unusual, so this is a targeted fallback,
not a first-line style rule. Prefer a real iterator/range struct when the
surrounding code provides evidence for one.

### 5. Low-word flag updates sometimes need an explicit 32-bit object

Several target clears touched only the low word of a 64-bit flags field. With
propagation disabled for this function, a local `u32` copy and mask reproduced
the load/mask/store web:

```c
u32 mask;
u32 stateFlags = state->stateFlags;
mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
state->stateFlags = stateFlags & mask;
```

This was better evidence for the target operation width than a raw dereference
cast such as `*(s32*)&flags`. It should only be used when the target clearly
loads and stores one word; it is not permission to truncate every 64-bit flag
operation.

### 6. Literal spelling can affect pool and temp reuse

The timer clamps matched with ordinary `0.0f` literals at the clamp sites, while
other comparisons needed the named `lbl_803E23DC` load. Equal-valued literals
and globals are not interchangeable to MWCC: they can change first-use order,
pool ownership, and whether a value is considered runtime-unknown.

Likewise, redundant `(double)` casts around two `f32` operands changed codegen;
removing them recovered the direct single-precision comparison.

Treat these as local experiments. Check both `.text` and `.sdata2` whenever a
literal/global substitution is retained.

### 7. Separate code matching from reconstructed cross-object symbols

The final object has a compiler-generated signed-int-to-double bias at the
correct `.sdata2` address. Objdiff may call the source symbol `@N` while the
reconstructed target calls it `gTrickyS32ToDoubleBias`; the code and data bytes
still match. Several not-yet-linked neighboring Tricky splits reference the
reconstructed global name, so `dll_00C4_tricky` cannot yet be promoted alone
from `NonMatching` without solving that cluster-level ownership problem.

Do not distort the C conversion expressions or add duplicate constants merely
to rename this compiler-generated pool entry. See
`INVESTIGATION_intfloat_magic.md`. Revisit the conclusion if a clean compiler or
linker mechanism is found; the current evidence only says that the attempted
source-level definitions added or reordered data.

## Attempts that were useful failures

- Scalar counter declaration/order mutations: showed the extra zero was a web
  reuse problem, not loop control flow.
- `u8` loop counter: proved register reuse was reachable, but contradicted the
  target signed compare/extension sequence.
- `do`/`while` and increment-free loop forms: unnecessary once the lifetime was
  right; the natural `for` form remained exact.
- Manual signed-int conversion using a union/bit construction: emitted extra
  integer operations and/or `frsp`; it did not reproduce MWCC's special
  conversion opcode path.
- A named `f64` bias definition: emitted a second constant and changed `.sdata2`
  order instead of naming the automatic pool entry.
- Function-local tests alone: sometimes reproduced the desired registers but
  did not transfer to the real TU.

Failures are evidence about one IR and one TU, not bans on those source forms.

## Compact workflow for similar tails

1. Confirm that instruction count and control flow already match.
2. Classify each region: relocation alias, address association, GPR/FPR coloring,
   rematerialized constant, or real instruction mismatch.
3. Work in the full TU and score only the target function.
4. Try natural lifetime changes first: block scope, declaration order, separate
   iterator/cursor objects, and compound assignments.
5. For wrong-base addressing, vary the typed expression that owns the offset.
6. Use a small aggregate only when scalar spellings demonstrably cannot retain
   the required web.
7. Rebuild the real source, run `ndiff`, and verify the unit report; a scratch or
   permuter score is not the result.
8. Before publishing, run `timeout 30s ninja all_source`, the strict matching
   build, and the retail checksum.
