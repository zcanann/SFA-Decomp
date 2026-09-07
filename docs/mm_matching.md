# Memory manager matching (2026-09-07)

`src/main/mm.c` is now `MatchingFor("GSAE01")`: all 32 functions, 6,596
code bytes, and 17,848 data bytes match. The complete source-linked DOL passes
the strict retail checksum.

| Measure | Before | After |
| --- | ---: | ---: |
| Unit fuzzy match | 99.82899% | 100% |
| Exact functions | 30 / 32 | 32 / 32 |
| `mmFreeTick` | 98.72081% | 100% |
| `mmFreeDeferred` | 99.454544% | 100% |
| `mmFreeTick` instructions | 199 | 197 |

## Native storage and emission

The artificial `MmGlobalLayout` overlay is removed. The three BSS arrays have
independent definitions, with their original capacities and layouts:

| BSS offset | Definition | Bytes |
| --- | --- | ---: |
| 0x0000 | `gMmStoreArray[32]` | 128 |
| 0x0080 | `gMmDeferredFreeStack[2000]` | 16,000 |
| 0x3F00 | `gMmRegionTable[8]` | 160 |

The Dinosaur Planet reference's `src/memory.c` independently declares its
memory pools and deferred-free queue, and places initialization before
allocation/free operations. That lineage, the reverse EN function order,
and the native shared-base behavior support deferred emission here, as in
the save-game and Expgfx recoveries. The existing
`cflags_dll_noopt_noautoinline_deferred` profile retains GC/1.3,
`nopeephole,noschedule`, and `noauto`. Ordinary function definitions and
tentative BSS definitions are ordered for reverse deferred emission.
There is one TU and no per-function compiler setting.

`mmFreeTick` walks the deferred-free queue directly and resets each memory
store through a pointer cursor. Keeping the cursor before the store local,
and incrementing the cursor before the loop index, reproduces the retail
unrolling and register allocation. Region accounting uses the real region
table. Every instruction now agrees, including the two removed instructions.

`mmFreeDeferred` saves the incoming allocation pointer before draining a full
queue. It reuses the argument as the queue end pointer during the drain,
with narrow `DeferredFree*` casts at its accesses. This lifetime reproduces
the six previously reversed r3/r4 operands. A separately declared end-pointer
local changes register allocation. The drain's swap-with-last behavior and
the final append are preserved.

## Diagnostic ownership

The 1,480-byte initialized-data span contains 22 diagnostic strings, including
unused memory-store diagnostics. They now have ordinary named array
definitions and direct uses. Two imported byte blocks are replaced by their
individual strings, and the active symbol config records their boundaries.
There are no manual offsets between unrelated arrays.

With all definitions available during deferred generation, MWCC creates its
own shared data base for the functions that use several messages. This also
preserves the complete data span during linking. The earlier manual base
pointer only named the first array, allowing the linker to discard 416 bytes
of messages reached through offsets. A source-object-only comparison missed
that failure; the full DOL checksum verifies the recovered ownership.

The emitted strings occupy 1,474 bytes, followed by the original six bytes of
section alignment. All initialized bytes and the named BSS/SDA offsets are
preserved. No duplicate constants, forced sections, or linker-retention
exceptions are added.

The canonical `main/mm.h` now declares `mmInitRegion` and the two existing
heap-selection setters, replacing stale setter names. The TU includes that
header first; its private storage types remain local.

## Validation

- `ninja all_source` exits successfully.
- The matching build passes `config/GSAE01/build.sha1` with `mm.c` linked
  from source; the resulting DOL is byte-identical to the preceding retail
  build.
- Objdiff reports all 32 functions and all 17,848 data bytes exact.
- Named BSS/SDA offsets and every diagnostic's bytes and offset are audited
  separately from objdiff's normalized relocations.
- Formatting is a separate commit, verified against the complete compiled
  object. The source and header pass `clang-format --dry-run --Werror`.

Both Ninja invocations use a 30-second timeout.
