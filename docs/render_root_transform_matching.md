# `modelRenderInterpolateRootTransform` matching

`main/render.c` is 100% code and data (10/10 functions) as of 2026-09-25. The last function,
`modelRenderInterpolateRootTransform` (2 212 B), went from 96.682 to 100 in five source changes.
Each was found by reading GC/1.3 backend captures (`tools/tricky_backend_trace.py`) and LLDB hooks
on the IR range splitter, not by sweeping.

## Provenance

Dinosaur Planet implements the same decoder as hand-written MIPS: `func_8001CAA4` in
`asm/model_asm.s`. It uses the same `ObjAnimState` offsets (`0x2C` cursor, `0x34` descriptors,
`0x4C` stride). The SFA C reads like a port that keeps each 64-bit MIPS register as a `u64`/`s64`
local: `curB` is `a3`, `posA` is `t0`, `bufA`/`bufB` are `s3`/`s7`, `h` is `s0`, `nib` is `s1`
and `bitpos` is `s2`. This explains the pointer arithmetic done in 64 bits. It also explains
`curB += posA` (`addu a3,a3,t0`) and the in-place `h &= 0xFFF0` (`andi s0,s0,0xFFF0`).

## The five levers

1. **`sample = h` after the shifts.** Retail computes `h + …` into its own register and copies
   it into `sample` (a volatile register) after the two `__shl2i` calls. Writing
   `h += …; …shifts…; sample = h;` reproduces the copy. Computing `sample` directly keeps it live
   across the calls instead.
2. **`u64 h` with `h &= 0xFFF0`.** Both hi-word `and`s survive only when `h` is `u64` and the
   mask is a compound assignment. With `s64 h`, value numbering merges the hi `and` into `nib`'s.
   In the inner block, a bare `h &= 0xFFF0` whose only use is `sample = …` gets
   forward-substituted down to that use. The self-referencing `h += vA + tmp; sample = h;` blocks
   the substitution. The old `maskConst` local is unnecessary; the literal is hoisted and spilled
   to `64(r1)` either way.
3. **`curB += posA` with `s64 posA`.** Retail loads the stride directly into `curB`'s final
   register (r22). That requires two things. First, the load must not be forward-substituted
   into its use. A use in a statement that redefines the same variable blocks this. Second, the
   IR range splitter (`0x45d090`, which keeps the first and last components and splits the middle
   ones) must see the load and the loop definitions as one component. Only a compound assignment
   joins them, because its left-hand node is both the use and the definition. MWCC sign-extends
   the `int` in `c += p` only when `p` is `s64`; with a `u64` operand it emits `addze`. Measured
   in isolation: `c += u64` → `addze`, `c += s64` → `srawi`+`adde`, `u64 + c` → `srawi`,
   `c + u64` → `addze`.
4. **No `addrB`.** Once the prologue is compound, both refills can be `curB = bufA + curB` with
   the calls taking `curB`. The two refill macros become textually identical and are now one
   `RENDER_BITS_REFILL`.
5. **Declaration order, derived by solver.** After 1–4 the PCode matched retail and only the
   colouring differed. Projecting retail's registers onto the captured vregs gave no conflicts.
   `../mwcc/tools/solve_gc13_register_order.py` then found a scan order reproducing the full colour
   vector. Extra constraints kept each 64-bit lo/hi pair adjacent and kept spill-slot order
   (`frac` < `end` < `outPos`, which fixes the `40/52/56(r1)` homes). A z3 MaxSAT pass then
   minimised inversions against the previous order. Objects are numbered in reverse textual
   declaration order, so all locals are declared at function scope.

## Tooling added

- `tools/tricky_backend_ir.py` decodes `addc`/`adde`/`subfc`/`subfe`/`mulhwu` (PCode opcodes
  `0x3D`/`0x3E`/`0x4D`/`0x4E`/`0x48`). The capture's opcode alignment check verifies them.
