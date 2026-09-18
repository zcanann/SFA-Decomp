# Dynamic line-slot argument conversion

The retained `trackGetLineIntersect` has 414 instructions and seventeen operand
differences. They are confined to allocation of a cached dynamic-line slot.
Retail masks the query argument for the enable test, then stores the original
argument with `stb`. The reconstructed source instead keeps the masked value
live through the free-slot search and stores that value. The low byte is the
same, but its lifetime changes three physical register choices.

A September 17 GC/1.3 LLDB capture follows the difference through nineteen
backend stages. Traced and ordinary objects are raw-identical, SHA-256
`6aa15c92ee6ae57d0b9930a7d335f8196a9761d4b3ff02755e66bab5a25cc520`.
Before global optimization, the enable test masks argument virtual register 39
into register 102. The inlined K&R allocator separately masks it into register
62. First value numbering replaces that second mask with `mr 62,102`;
copy propagation redirects the byte store from register 62 to register 102.
The store continues using 102 through coloring, where it becomes r3. Retail
instead stores the original argument from r31, allowing the guard temporary to
use r0 and die before the search.

An ANSI allocator prototype with an `int` or `u8` parameter gives the retail
register choices, but leaves an extra `clrlwi` immediately before the slot-byte
store: 415 instructions instead of 414. It therefore does not establish a
match. A prior `int` prototype for the K&R definition has the same problem.
Moving the helper definition below its caller prevents the desired inlining.
Changing the enable test to an integer mask, changing signedness, or explicitly
narrowing the allocator argument also regresses the retained match. These
experiments are not source changes.

Reproduce the unchanged-source capture with:

```sh
python3 tools/tricky_backend_trace.py --unit main/main/track_dolphin \
  --function trackGetLineIntersect --graph --register-class gpr \
  --output build/track_complete/line_slot_trace
```

This identifies the responsible transformation, but does not yet recover the
source shape that emits retail's unmasked byte store.

## Emission-time narrowing check

A standalone probe under the unchanged track compiler flags confirms that
`void store(u8* p, int x) { *p = x; }` emits `clrlwi; stb; blr`. Explicit
casts, integer masks and an enum cast retain the conversion. A K&R byte
parameter emits just `stb; blr`. Changing the public sweep's slot parameter
to `u8`, however, hoists its normalization and changes register allocation;
it is not a matching fix and no public signature was changed.

An offline, hash-verified compiler capture locates the unsigned conversion
emitter's return site at `0x004e0351` and the byte-store emitter at
`0x004e8e59`. The narrowing emitter calls `0x004e0490` to recognize a
compatible conversion already at the current block tail. That complete
138-byte predicate is now reconstructed in the companion compiler project's
`src/versions/GC_1_3/Narrowing.c`, with 10,103 original/native comparisons,
all 54 reachable x86 instructions covered, and no dependency stubs.

The predicate only examines the immediately preceding emitted instruction:
same destination GPR and opcode, or `EXTSB` satisfying a requested `EXTSH`.
For `RLWINM`, rotation must be zero and both mask bounds must match exactly.
It does not search through the intervening comparison, branch, or slot-search
loop. Thus this emission-time shortcut cannot by itself recover the retail
store from an earlier guard's mask. No game source or compiler flags changed.

The complete normalization caller at `0x004e02a0` is now recovered as well:
7,728 original/native comparisons cover all 180 reachable instructions under
the diagnostic's non-returning contract. It saves the original operand's
memory classification before forcing it into a GPR. Loaded unsigned bytes and
loaded halfwords can skip normalization; register values follow the narrowing
checks described above. Signed-byte register allocation happens before the
redundancy check, so an omitted conversion can still consume a virtual ID.
The original tail predicate executes in this comparison; materialization,
signedness, emission, and diagnostics remain explicit dependency adapters.

Full-width byte bitfields do not remove the allocator's extra mask under these
flags, whether their base type is byte, halfword, or word sized. Making the
public slot argument a byte and varying the inline helper parameter types also
regresses the function. Neither record layout nor public signatures changed.
