# Scarab (object DLL 262)

EN v1.0, GC/1.3, 2026-09-07. The unit remains `NonMatching`: six of seven
functions are exact, all 240 assigned data bytes match, and `Scarab_update`
has one differing instruction in 3,476 bytes (99.930954%). Whole-unit text
is 99.95461% fuzzy matched.

## Collection helper

Dinosaur Planet's `src/dlls/objects/297_scarab/scarab.c` defines
`scarab_collect(self, player, objData)`. Its local byte table is
`{1, 5, 10, 50}`; it awards the indexed amount, sets the destruction delay
to 80, and clears the lifetime. Its callers are the queued pickup reply,
ordinary proximity collection, and the stunned rainbow-scarab hit.

The EN function contains that same operation at the same three behavioral
sites. `Scarab_collect` recovers this shared inline helper, replacing three
expanded bodies, three union temporaries, and the packed-word currency table.
The helper precedes the emitted collision functions so its initializer stays
at the beginning of the constant pool. Defining it immediately before
`Scarab_update` preserves instructions but reorders the pool; that variant
was rejected. `gScarabMoneyValues` in the target config now identifies a local
initializer rather than an exported object.

Compared with staging `dd8fa982c5`, every emitted function byte and every
allocated section byte is unchanged. Other named symbol layouts and
relocation destinations are unchanged; the currency-table references now
use the compiler's anonymous initializer. A diagnostic link substituting
the reconstructed object for the retail object differs only at
`0x80184998` through `0x8018499B`. All section addresses and lengths,
including the complete linked constant pool, match retail.

## Remaining zero initialization

At instruction 26 of `Scarab_update`, retail emits `mr r30,r31`; the current
compiler emits `li r30,0`. The earlier `li r31,0` and its store initializing
the ground-hit pointer are exact. Dinosaur Planet's source and MIPS assembly
both support separately initialized scalar ground-index and collision locals;
they do not support restoring the former one-element index array.

The existing LLDB provider can trace this unit directly:

```sh
python3 tools/tricky_backend_trace.py \
  --unit main/dlls/objects/262/262 --function Scarab_update --graph \
  --output build/flag_probe/scarab_backend
python3 tools/tricky_backend_trace.py \
  --read build/flag_probe/scarab_backend/trace.json \
  --function Scarab_update --instruction 8 --instruction 26
```

The pre-recovery baseline capture contains 20 stages and 869 final
instructions. Its instrumented and ordinary objects have the same SHA256:
`3f6b9af298a7395a7d1cd6068f073a1c6c749b9b088bc8cd1971cbeea5c20bde`.
Both register graphs validate, and all 202 physical-color choices replay.
The recovered helper was traced again with the same stage counts, register
numbers, and remaining instruction. Its ordinary and instrumented SHA256 is
`73c6eac6b8dafec48197fddba763cb7f9e0801fcd79f800f5b41b842ed33ee0e`.

The baseline zero loads already exist before global optimization. The initial
ground index uses virtual GPR 52, within the observed late value-numbering
range `[46, 237]`; the collision flag uses GPR 44, outside it. The pass
combines the ground-pointer zero with GPR 52 but leaves the flag's `li`
unchanged. Thus this particular instruction is not first introduced by
allocator rematerialization, as the older `priced_classes.md` discussion
suggested.

Reusing the collision-result scalar for the gold-climb swept query moves its
initial lifetime to GPR 50. LLDB observes the desired `mr` after the second
value-numbering pass, but register coalescing subsequently removes it and
changes other register assignments: 868 instructions, 99.75835%. This variant
was rejected. It demonstrates that source lifetimes can reach the copy;
it does not reproduce retail's allocation.

Separate query-result locals, ground-loop index reuse, scalar widths,
declaration initializers, a shared closest-hit reduction, and the collection
helper do not resolve the remaining instruction. Diagnostic changes to
lifetimes, propagation, CSE, optimization level, deferred inlining, and
language mode also fail to produce an exact unit. Production compiler flags
and TU boundaries are unchanged. These observations describe the tested
source forms, not a proof that matching clean C is impossible.
