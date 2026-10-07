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

## Native allocation and memory-store contract (2026-10-06)

The allocator now keeps native pointer widths from region initialization through
the returned allocation and memory-store cursor. `mmAllocFromRegion` returns
`void*`; `MmStore` owns byte pointers; store allocation uses `sizeof(MmStore)`.
The retail record remains 16 bytes. Region alignment and split diagnostics use
signed `ptrdiff_t` address values. An unsigned address local changes the EN
alignment comparison from `cmpwi` to `cmplwi`; the signed form preserves it.
Foxhollow's `game/src/main/mm.c` independently widens these address paths.
This recovery does not replace the hardware arena setup in `mmInit`.

`mmAlloc`'s third argument is a nullable diagnostic name. Retail passes it to
the `%s` allocation failures; the two store allocations supply string pointers.
All 200 other source calls supply zero, including the ECSH creator's named
macro. Dinosaur Planet's `src/memory.c` independently declares the same argument
as `const char* name`. The public prototype, private forwarding arguments, and
native test stubs now express that contract without pointer-to-int laundering.

Game text is the store allocator's only source client. Its global is now
`int gGameTextStringStoreHandle`, initialized to `-1`, with the same four-byte
small-data location in every version. Renderer initialization and line wrapping
pass the integer handle directly. The native initializer test and retail/source
wrapping probe use handle 37 instead of treating it as a pointer.

Retail behavior is preserved: the first successful store can return zero, also
used for failure; a failed backing allocation consumes a handle; exhausting all
32 store slots releases the buffer before the store record. Frame ticks reset
live store cursors. Zero-sized requests return the current cursor, and negative
requests can rewind it without validation. The space-error call still omits
arguments for its two `%d` slots. The existing one-element `requestedSize` local
is retained: a scalar changes MWCC register allocation in this exact function.

Validation:

- `tools/test_mm_stores.py` executes production region setup, allocation,
  splitting, freeing, stores, and frame ticks at `-O0` and `-O2`, with ASan and
  UBSan. Its 45 scenarios cover full-width pointers, allocation routing and
  fallback, sizes at routing/alignment boundaries, handle lookup through holes,
  cursor limits, immediate/deferred failure cleanup, and heap accounting.
  Five temporary negative controls detect region, allocation-return, and
  store-return truncation, a truncated diagnostic name, and a missing reset.
- The updated consumer fixtures pass. The wrapping probe compares retail and
  compiled code across 151 cases, including the integer handle passed to the
  store allocator.
- All five versions pass `all_source` and the strict checksum build, with each
  input hash verified and each output DOL byte-identical to its original.
  All four touched TUs are 100% in every version. The complete inventory has
  no new mismatches; the existing TRK `__exception` vector-boundary and MusyX
  `sal_volume` discarded-exception-data report artifacts remain unchanged.
- Every source object except the two game-text objects is byte-identical to
  its baseline, including `mm.o` and the ECSH creator. Those two differ only
  in the store-handle symbol name; section contents, symbol layouts, and
  relocations agree after that explicit rename. Compiler settings and TU
  boundaries are unchanged.
