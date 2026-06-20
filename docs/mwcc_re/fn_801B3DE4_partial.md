# fn_801B3DE4 (dll_01CA_dimexplosion) — documented partial @ 98.04%

Per the prime directive: residual that won't yield → commit the partial, document the
target-vs-ours asm shape, keep on the retry list.

## State
- Unit: `src/main/dll/DIM/dll_01CA_dimexplosion.c`, compiler GC/2.0 (`-O4,p`).
- `fuzzy_match_percent` = **98.0387**. Pragmas: `peephole off`, `opt_propagation off`.

## The single divergence
Saved-register allocation is otherwise correct (`state→r28`, `off→r30`, `e→r31`). The
target keeps a SECOND callee-saved register holding the same value `state+off`, used
only for the `0x14` field, established by a copy right after the `sqrtf` call:

```
target:  add r31,r28,r30        mine:  add r31,r28,r30
         ...                            ...
         bl  sqrtf                      bl  sqrtf
         ...                            ...
         mr  r29, r31     <-- MISSING   (folded)
         stw r0, 0x14(r29)              stw r0, 0x14(r31)
         ...                            ...
         lwz r0, 0x14(r29)              lwz r0, 0x14(r31)   (all 0x14 use r31)
```

`e` and `e14` both equal `state+off`. O4 value-numbering proves them equal and
substitutes `e14→e`, eliminating the copy (no `mr`, and the `0x14` accesses use `r31`).
The target keeps two registers for the same value connected by `mr r29,r31`.

## Root cause (localized via compiler RE tooling)
The fold is in MWCC's value-numbering pass — `ValueNumbering.c`, mapped to `mwcceppc.exe`
@ `0x509010` by `tools/mwcc_assert_map.py`. This matches the existing CLAUDE.md worked
example: "the `mr r29,r31` base copy that O4 value-numbering folds away."

## Source levers tried — ALL fold to one register (byte-identical or no `mr`)
1. `e14 = e` (copy)                              8. `register int e14`
2. embedded-assign in store addr (#116)          9. phi via `if(b==0xff) e14=e` (#94)
3. post-`sqrtf` sequencing of `e14=e` (#94)      10. phi via `b ? e : state+off`
4. `char* e14` retype (#77)                      11. `optimization_level 0/1/2/3` (#95/#108)
5. `(int)(long)e` VN-split (#114)                12. `opt_common_subs off`
6. fresh memory re-deref `*(obj+0xb8)+off` (#130)13. un-naming / inline `(state+off)` (#107)
7. `e14 = state + idx*0x30`                       + decl-order/hoist brute battery
None produced `mr r29,r31`. Confirmed by objdump grep on the rebuilt `.o` each time.

## Why dynamic instrumentation didn't help (on this host)
arm64 Mac: `mwcceppc.exe` (32-bit PE) runs under wibo via i386 LDT code segments under
Rosetta 2. lldb breakpoints at the PE's VAs (`0x509010`) don't hit — the guest code is
mapped at an unknown high host address through a segment, not at its flat VA. Reaching it
needs RE of wibo's guest-memory model, or a Linux x86 host where gdb can break at the VA.

## Verdict / retry list
100% requires the `mr r29,r31` copy, which O4 value-numbering folds unconditionally for
this expression. No clean-C lever found; inline asm is forbidden. Banked at 98.04%.
Next genuine attempts: (a) static RE of `ValueNumbering.c` @ 0x509010 to find the exact
non-fold condition; (b) Linux-host dynamic instrumentation of the same address.
