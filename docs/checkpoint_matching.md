# Checkpoint routes (engine DLL 3)

EN v1.0, GC/1.3, 2026-09-07. All 18 functions (8,248 text bytes) and
all 1,884 assigned data bytes match. The unit is `MatchingFor("GSAE01")`
with its existing compiler profile and boundaries.

## Control-point construction

`Checkpoint_buildControlPoints` already had the retail 625-instruction
structure and Hermite tangent equations. Its remaining 81 differing operands
were general-purpose register assignments across the route lookup, output
loop, and individual-point modes.

Two local records express the state carried through those operations:

- `segment` holds the start checkpoint and the selected linked endpoint.
- `cursor` holds the three axis-output pointers and their shared point index.

The records are transient calculation state, not newly claimed game-object
layouts or recovered original type names. MWCC scalarizes them into the
retail registers without adding stack storage or instructions. Grouping only
the endpoints reduces the differing operands to 53; the complete write cursor
resolves the rest. Keeping the cursor's point index together with its output
pointers is significant to that allocation.

Each axis still contains two endpoints followed by two Hermite tangents. The
all-points mode emits four groups of four floats per axis. The selected-point
and explicit-offset modes preserve their existing array accesses and tangent
calculations. Link fallback and return values are unchanged.

## Validation

- Objdiff: 18/18 functions, 100% code and data.
- Raw `.text`, `.data`, and `.sdata2` bytes equal retail.
- `.bss` and `.sbss` sizes agree, and common named data symbols retain their
  retail section offsets and sizes.
- `ninja all_source` and the strict source-linked retail checksum pass.
- DOL SHA1 remains `e750e8e894707a52446118a4b84f1b58b677b269`.
- Formatting is committed separately and preserves the complete object bytes.
