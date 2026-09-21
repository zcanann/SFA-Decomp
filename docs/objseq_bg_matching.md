# ObjSeq_runBgCmds matching

`ObjSeq_runBgCmds` matches **100%** in EN, EN rev1, JP, PAL, and PAL rev1.
All 952 bytes / 238 instructions match through objdiff, including register
operands. The original 69 differing instruction words fell to 20, then 14,
and finally zero. At this milestone, the complete EN DLL improved from
99.78571% to 99.833725%;
other functions still prevent marking the whole translation unit `Matching`.

## Retained source

The function keeps separate `index` and `xrot` locals and groups its command
and object-list pointers in a local `cursor` record. It initializes
`cursor.objPtr` before `cursor.cmd`, then resets the object cursor for each
queued command. Local declarations are ordered to reproduce allocation.

The first object-cursor initialization is redundant at runtime, but its
position matters to compilation: field promotion encounters that member first.
Removing it or reversing the two initializations produces eight differing
instruction words.
The cursor record is a source reconstruction hypothesis, not evidence of an
externally stored game structure. It requires no stack storage in the output.
No compiler settings, per-function pragmas, assembly, globals, or TU boundaries
were changed.

## Compiler evidence

The stock GC/1.3 compiler SHA-256 is
`4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715`.
Native macOS LLDB captures record 20 stages and the 142-node GPR graph.
The final traced complete object is byte-identical to an ordinary build.
Simplification and physical coloring replay exactly, without spills.

The sibling `mwcc` project's recovered `ObjectRegisterWalk.c` and
`RegisterIdentity.c` establish that named locals are assigned identities in
reverse declaration order, before compiler-generated locals. Its
`IROFieldAccess.c` records aggregate-member accesses in first-encounter order;
field promotion gives those members generated identities. These identities
control simplification order and therefore the physical register assignment.

Declaration reordering alone reached 99.47479%. Copying the queued command
into a local record reached 99.60084%, with two register swaps remaining.
Both fixed graphs had UNSAT exact-color queries when only named identities
could move. An expanded query found an exact abstract ordering by exchanging
the identity groups of the two command fields and the two traversal cursors.

The retained source realizes that prediction. Initializing the object cursor
before the command cursor gives their generated identities the required order.
A solver-selected named declaration order then compiles to zero differences.
Merely reversing record member declarations did not produce this result.
The final capture maps `cursor.cmd` to r24, `cursor.objPtr` to r25, `xrot` to
r19, `index` to r20, and the runtime-buffer base to r26, exactly as in retail.

`capture_symbol_objects` now also reads object pointers retained in allocator
nodes. Previously, register-only local names were omitted when they no longer
appeared as symbolic instruction operands. This read-only capture improvement
and its regression test distinguish named and generated locals directly.

The [captured coloring input](objseq_bg_register_order.json) preserves the
final graph, local names, allocator policy, baseline colors, and retail colors.
The baseline and retail vectors are identical. With the sibling repo and Z3:

```sh
python3 ../mwcc/tools/solve_gc13_register_order.py \
  --input docs/objseq_bg_register_order.json \
  --output /tmp/objseq-bg-order.json
```

The result is SAT and its allocator replay is verified. This models the
captured graph; the ordinary compiler and objdiff independently establish the
actual source match.

## Validation

- All five original DOL hashes verified before regional objdiff comparisons.
  PAL's original and target object came from the sibling SFA checkout because
  this checkout lacks its original DOL.
- Objdiff reports 100% for this function in every region. No other function's
  score changes. EN machine-code comparison likewise changes only this function.
- EN named symbol offsets/sizes and every non-text section's bytes, size,
  and alignment remain unchanged. Compiler-generated anonymous symbol numbers
  change, but relocation sites, types, addends, target sections and target
  offsets remain identical, as do all named relocation targets.
- `ninja all_source build/GSAE01/ok` exits zero and reports
  `build/GSAE01/main.dol: OK`.
- `clang-format -i` applied; `clang-format --dry-run --Werror` passes.
- Backend graph, IR, and LLDB capture tests pass (84 tests).
