# Curve collision (engine DLL 21)

EN v1.0, GC/1.3, 2026-09-07. All 31 functions (11,468 text bytes) and
all 1,008 assigned data bytes match. The unit is `MatchingFor("GSAE01")`
and links from C. Its boundary, compiler version, and optimization profile
are unchanged.

## Point transforms

The former `curves_advanceCollision` reconstruction maintained four explicit
walkers: a component index, a point index, a destination byte cursor, and a
source byte offset. Only its first source-offset initialization differed from
retail: `li r26,0` instead of `mr r26,r29` at instruction 61.

The five transform loops now derive their source and destination pointers
from the component index. The destination pointer is assigned first. MWCC
strength-reduces the address expressions into the retail byte-stride walkers,
including the missing copy and the order of both pointer increments. The
component and point counters form a local two-field record; it describes
transient traversal state, not a newly inferred allocation or original type
name. The explicit source byte offset and the one-element destination-cursor
array are gone.

The two raised-point copy loops use a scalar byte cursor, with field offsets
expressed through `offsetof(CurvesCollisionState, ...)`. Their count shares
the existing integer index used for parent-matrix selection. These phases do
not overlap. Splitting that index into a fresh copy-only local changes register
allocation; retain the shared lifetime. Ordinary indexed copies also change
allocation. Neither alternative is evidence that the previous one-element
cursor array was original source.

## Compiler evidence

A diagnostic GC/1.3 backend capture of the scalar baseline observes the first
zero assignment before global optimization. Its destination, virtual GPR 35,
is outside the late value-numbering pass's immediate-commoning range
`[39, 224]`. Later loop assignments fall inside that range. This is more
specific than the earlier claim that the difference was source-inaccessible
allocator rematerialization.

The matching capture has 618 final instructions and no retail differences.
The diagnostic compiler process and an ordinary compile produce identical
objects. No compiler file, production flag, volatile access, assembly body,
or section-placement directive is changed.

## Validation

- Objdiff: 31/31 functions, 100% code, 100% data.
- Raw `.text`, `.data`, and `.sdata2` bytes equal their retail objects;
  `.bss` and `.sbss` sizes also agree.
- `ninja all_source` and the strict matching build both pass.
- The source-linked DOL is byte-identical to retail, SHA1
  `e750e8e894707a52446118a4b84f1b58b677b269`.
- Formatting is committed separately and preserves the complete object bytes.
