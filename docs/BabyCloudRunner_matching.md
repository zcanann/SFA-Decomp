# Baby CloudRunner (DLL 332) matching

The 2026-09-07 recovery factors the three identical capture predicates into
`babyCloudRunner_canCapture` and the four animation restarts into
`babyCloudRunner_startMove`. The common GC/1.3 compiler automatically inlines all
seven calls with the ordinary `cflags_dll_noopt` profile. The unit remains
`NonMatching` because its literal pool is not yet exact.

All 14 retail functions (4,428 bytes) retain their exact instruction bytes and
literal-load value sequences. The 128-byte `.data` and 40-byte `.sdata` sections
remain exact. The `.sdata2` size increases from 64 to the retail 68 bytes, and its
objdiff section score improves from 66.66667% to 88.2353%. The matched-data counter
remains 168/236 because the remaining pool is still an incomplete section.

The helper declaration order and ordinary automatic inlining emit the retail
pool prefix: `0.0f`, four alignment bytes, and the signed integer-conversion bias.
The compiler emits out-of-line helper copies as well. A diagnostic link replacing
only the retail 332 object strips both copies, retains the full pool, and preserves
all retail function addresses and sizes. Its only allocated-section differences
are the reordered `.sdata2` bytes and their `.text` SDA relocations.

Local declaration order matters in the capture helper and its descriptor caller.
GC/1.3 backend captures through LLDB reproduced ordinary object hashes; extraction
initially swapped the capture-result and state registers in the two prompt paths.
Declaring the state before the result recovers the original register allocation.
The generic-pointer assignment in `tryCapture` is retained.

Two literal placements remain unresolved:

| Literal | Current pool offset | Retail pool offset |
| --- | --- | --- |
| `1.0f` | `0x2C` | `0x10` |
| `10.0f` | `0x34` | `0x20` |

The remaining literals preserve their relative order. The only surviving EN
loader of `1.0f` is the render callback; `10.0f` is used by update's curve motion.
Moving or reversing whole function definitions and using deferred inlining did
not reproduce the retail pool while retaining its text order.

Dinosaur Planet's `CFCloudBaby` object maps to DLL 373. Its binary retains older
Hermite length and movement helpers, including a length routine that uses zero
and signed conversions. The saved SFA debug Ghidra database contains a smaller,
older CloudRunner implementation. Neither reference currently establishes the
missing EN bodies or declarations for the two remaining literal placements.

Validation: `python3 configure.py --matching`, `ninja all_source`, and the strict
`ninja` checksum target pass. The checksum build still uses the retail 332 object;
it does not establish that this C object's unresolved pool matches.
