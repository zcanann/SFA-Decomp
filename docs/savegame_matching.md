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
