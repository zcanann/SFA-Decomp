# Pragmas heavily used in this codebase → which compiler pass each one gates

Empirical frequency across `src/` (`#pragma X on/off/reset`), most-used first,
mapped to the `mwcceppc.exe` (GC/2.0) TU/pass it controls. This is the "which
knob touches which decompiled pass" index for the RE effort.

| count | pragma | gates pass / TU | binary band | RE status |
|------:|--------|-----------------|-------------|-----------|
| 358 `off` / 181 `on` / 74 `reset` | `peephole` | **Peepholer** — inlined into the PCode emit TUs (no own assert-TU) | `PCodeListing.c` 0x500c40 region (TBD) | not located |
| 312 / 130 / 70 | `scheduling` | **`Scheduler.c`** list scheduler | 0x508100-0x508680 | ✅ decompiled |
| 236 / 33 / 212 | `dont_inline` | inliner (`CInline.c`) | 0x55bcb0-0x5624a0 | not started |
| 106 / 4 / 102 | `opt_common_subs` | **CSE**: `IroCSE.c` + `ValueNumbering.c` | 0x46a360 / 0x509010 | not started |
| 55 / — / 47 | `optimization_level` | global `-O0..4,p`; sets which IR passes run | `COptimizer.c` 0x4fd9d0 | not started |
| 52 / 3 / 49 | `opt_propagation` | copy/const propagation | `IroPropagate.c` 0x470060 | not started |
| 34 / — / 32 | `opt_loop_invariants` | LICM | `LoopOptimization.c` 0x572e90 | not started |
| 27 / 7 / 18 | `fp_contract` | FP fuse (fmadd) — `InstrSelection.c` | 0x444370 | not started |
| 21 / 6 / 17 | `opt_strength_reduction` | `StrengthReduction.c` | 0x571730 | not started |
| 15/11 | `ppc_unroll_speculative` | `IroUnrollLoop.c` | 0x4a1080 | not started |
| 12 | `ppc_unroll_instructions_limit` / `_factor_limit` | `IroUnrollLoop.c` | 0x4a1080 | not started |

Register **coloring** has no pragma (always on) — it is the silent pass behind most
"why this register" mismatches, which is exactly why decompiling `Coloring.c` is the
priority once `Scheduler.c` is verified.

## The matching-critical trio
The pragma stack that dominates the hard residual functions (e.g. the blog's
`fn_801B3DE4` carried `peephole off` + `opt_propagation off` under `-O4,p`) is:

- **`peephole`** — local fixups *after* scheduling/regalloc. `off` freezes the
  instruction stream so what scheduling+coloring produced is what you see. When a
  function carries `peephole off`, the asm shape is purely a scheduling+coloring
  artifact — so the two passes we're decompiling fully determine it.
- **`scheduling`** — reorders within a basic block per the DAG in `Scheduler.c`.
  `off` ⇒ instructions stay in InstrSelection emission order; the dependency DAG
  is still built but the ready-list emit is bypassed.
- **`opt_common_subs` / `opt_propagation`** — decide whether a repeated address/
  value becomes one web (folded, reused register) or survives as a copy (the `mr`).
  This is `ValueNumbering.c` / `IroCSE.c`.

Practical read: a function under `peephole off; -O4,p` whose only divergence is a
register choice or an instruction order is **fully explained by `Coloring.c` +
`Scheduler.c`** — no peephole noise in the way. Those are the functions to retry
first once both passes are decompiled and their levers are known.
