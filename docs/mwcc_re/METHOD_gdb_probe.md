# METHOD: dynamic-RE probe of mwcceppc allocator (x86_64 Ubuntu) — CONFIRMED WORKING 2026-06-23

Reusable procedure for breaking inside the running compiler at guest VAs. Confirmed on
gdb 15.1 / native x86_64. **This is a DISCOVERY tool — use what it shows to write clean,
plausible-2002 C. Never to justify a coercion hack.**

## How to break (confirmed hits)
1. Get the single-unit compile command, drop the `sjiswrap` wrapper for a non-SJIS unit
   (invoke `mwcceppc.exe` directly under `wibo`), e.g.:
   `build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe <flags> -c src/.../unit.c -o /tmp/x.o`
2. wibo (x86_64 ELF at 0x70000000+) maps the 32-bit PE at image base **0x400000**, no ASLR.
   gdb can't set a guest-VA breakpoint before the PE is mapped, so break at wibo's
   mode-switch thunk first:
   ```
   break call_EntryProc      # 0x703ca73c in the checked-in wibo
   run
   break *0x508680           # NOW the guest VAs resolve
   delete 1                  # drop the thunk bp
   ```
3. `commands N / silent / ... / continue / end` blocks count or inspect each pass entry.
   IMPORTANT: `silent` MUST be the first line of a `commands` block.

## Guest VAs (image base 0x400000, from assert_map_GC2.0.txt)
- Coloring.c          0x508680  0x508900  0x508c10 (coalescer)
- ValueNumbering.c    0x509010
- IroCSE.c            0x46a360    IroPropagate.c 0x470060

## Confirmed observable: pass-entry profile
controllight unit (one compile): Coloring@508680=9 @508900=4 coalescer@508c10=4
ValueNumbering@509010=57. (9 ≈ functions in the unit; coalescer 4 = fns with copies to
fold.) Profiling A vs B variants of a stuck fn isolates which pass diverges.

## Open / harder: reading the web→register RANKING
Counting hits is trivial. Reading the *allocation order* (which web gets which saved reg, and
why) needs the Coloring.c arg/struct layout (web list, interference graph) — that is genuine
mwcceppc data-structure RE (the README's "Coloring.c under-covered" frontier), not yet mapped.
Static disasm of 0x508680 + IDA/Ghidra on the anchors is the next step for that.
