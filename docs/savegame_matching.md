# Save-game engine DLL 23 matching

EN GSAE01 uses the common GC/1.3 compiler and its existing
`cflags_dll_noopt_noautoinline` profile. The unit remains `NonMatching`.

| Measure | Before | After |
| --- | ---: | ---: |
| Unit fuzzy match | 99.704865% | 99.752045% |
| Exact functions | 52 / 54 | 53 / 54 |
| Exact code bytes | 6,748 / 8,308 | 7,252 / 8,308 |
| Exact data bytes | 5,524 / 5,524 | 5,524 / 5,524 |
| `insertHighScore` | 99.36508% | 100% |
| `SaveGame_gplaySetObjGroupStatus` | 97.981064% | 98.04924% |

High-score insertion now indexes the canonical `SaveData.scores` table directly.
Removing the cached row-base pointer resolves the remaining r11/r12 permutation
without changing the 504-byte function size. `getHighScoreEntry` uses the same
table, and the redundant padded `SaveScoreFile` overlay is removed. The integer
base used for the final initials stores remains codegen-significant: replacing
all those accesses with normal pointer arithmetic regressed the function.

The transient-slot allocator scans with a cursor while retaining the index for
the destination stores. Its update order gives a small instruction-order gain.
The first store can also precede the destination-pointer assignment as separate
statements, preserving the generated object and removing the compound assignment
expression.

Only these two function bodies change: 14 instruction bytes in high-score
insertion and four in the map-group update. All other function bytes, allocated
section sizes/alignment, named-symbol layouts, data bytes, and relocation
destinations are unchanged. Anonymous literal symbols are renumbered.

The remaining map-group function emits 1,072 bytes against retail's 1,056.
Retail folds the five unrolled search iterations into displacements
`0/1`, `3/4`, `6/7`, `9/10`, and `12/13`, then advances the cursor by 15.
The reconstruction advances by three each time, adding four instructions.
The allocation loop also retains scratch-register differences. The standalone
`SaveGame_findTransientMapBit`, using the same search helper, remains exact.
Element-pointer locals, equivalent guards, alternate helper boundaries,
counter declarations, and direct caller-side searches did not resolve both
contexts without regressions. This does not establish a compiler exception.

The GC/1.3 backend tracer now recognizes and checks `andi.` and `not`, needed
to inspect these functions. Both baseline and final captures reproduce their
ordinary objects exactly, validate instruction alignment, and replay register
coloring. The final raw object SHA256 is
`e10b0369a10dace1743b0f952447757aaf8dec7487deb484b7c6ba055f16ef73`.

```sh
python3 tools/unitfuzzy.py dlls/engine/23/23.c
python3 tools/ndiff.py dlls/engine/23/23.c insertHighScore
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/23/23 \
  --function insertHighScore --function SaveGame_gplaySetObjGroupStatus \
  --graph --output build/flag_probe/savegame23_backend
```

`python3 configure.py --matching`, `ninja all_source`, and strict `ninja` pass
with `main.dol: OK`; each Ninja invocation has a 30-second timeout. Backend
tool tests pass, including malformed mask and corrupted instruction checks.

## Map-group follow-up

A second pass tested 51 compiled variants without improving the function's
98.04924% match. The game source and ordinary object remain unchanged. Search
counter widths, loop exits and bounds, byte/record addressing, inline boundaries,
and allocator index/address reuse either reproduced the baseline or regressed.
The exact standalone search was checked alongside the inlined search.

The frontend trace rejects its own search-loop unrolling because the loop has
multiple exits, then strength-reduces indexed accesses into a walking pointer.
The backend subsequently unrolls that loop five times. Its snapshots contain
two stride-three `addi` instructions before global optimization (one per search
or allocation loop), six after loop transformations, and six in final code.
Thus the four extra cursor updates are already present immediately after backend
unrolling; later propagation does not combine them. Track the complete loop at
each stage: compiler arena addresses can be reused for unrelated instructions.

Enabling peephole optimization as a scratch diagnostic combines intermediate
pointer updates with loads into `lbzu`, but does not reproduce retail's increasing
load displacements and regresses other functions. A complete global record in
place of the current overlay also leaves the search updates intact. Neither
experiment supports a compiler/profile exception or proves a source-level fix
impossible.

The frontend capture reproduces the same ordinary object hash listed above:

```sh
python3 tools/mwcc_frontend_trace.py --unit main/dlls/engine/23/23 \
  --function SaveGame_gplaySetObjGroupStatus \
  --function SaveGame_findTransientMapBit \
  --output build/flag_probe/savegame_group_frontend
```

## Pointer-propagation follow-up

The four extra cursor updates survive because of the backend's address
propagation checks. In the baseline capture, each stride-three update carries
`gTransientMapBits` as its known global symbol. When the post-unrolling pass
considers combining that update with the following byte load, it rejects the
candidate at GC/1.3 compiler PC `0x569e69`. The analogous map-status cursor
updates have no known global symbol and are combined successfully. These are
compiler-process addresses, not game addresses.

A scratch diagnostic that initializes the caller's record pointer from a
`static SaveGameRecord* const` reproduces all five retail search displacements
and the final stride of 15. It scores 99.15909% for the function, but replaces
retail's address construction with a pointer load and emits additional pointer
data. It is not a valid matching improvement. Local aggregate initializers,
pointer union views, and indirect local-pointer accesses can also remove the
search updates, but introduce stack stores or reloads. None was retained.

Direct and shared-counter search/allocation bodies, helper return types,
register qualifiers, pointer qualifiers, and complete-record declarations did
not improve the ordinary function while preserving its exact siblings. The
next source investigation should account for both the initial record address
and the compiler's tracking of that address through the inlined search; changing
only the loop's counter or exit spelling does not remove this propagation
barrier. The source, compiler profile, and ordinary object remain unchanged
from the hash recorded above.
