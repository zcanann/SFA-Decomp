# Save-game engine DLL 23: complete EN match

`SaveGame_gplaySetObjGroupStatus` and the complete save-game unit now match
EN GSAE01 and link from source. The source-linked DOL passes the strict retail
checksum.

| Measure | Before | Complete |
| --- | ---: | ---: |
| Unit fuzzy match | 99.752045% | 100% |
| Exact functions | 53 / 54 | 54 / 54 |
| Exact code bytes | 7,252 / 8,308 | 8,308 / 8,308 |
| Exact data bytes | 5,524 / 5,524 | 5,524 / 5,524 |
| `SaveGame_gplaySetObjGroupStatus` | 98.04924% | 100% |
| Setter size, retail 1,056 bytes | 1,072 | 1,056 |

## Source structure and emission

The local Dinosaur Planet reference's `src/dlls/engine/29_gplay/gplay.c`
provided the useful change of direction: its map lookup and object-group
status tables are independent globals. Its constructor precedes the gameplay
functions in source. It does not contain SFA's transient-entry logic, so that
part is recovered from the EN instructions rather than borrowed from N64.

The former `SaveGameRecord` combined five independent buffers behind a cast
from the 60-byte transient array. A common register base had been mistaken
for a source struct. The setter and initializer now access the real arrays,
and the transient helpers take the entry array directly. Allocation uses three
ordinary indexed field stores. The one-element pointer local and the cached
search/allocation cursors are removed. `suppressTransient` names the actual
role of the flag set by status `-2`.

The unit keeps GC/1.3, `nopeephole,noschedule`, and `noauto`. It adds deferred
emission using the existing `cflags_dll_noopt_noautoinline_deferred` profile.
Ordinary function definitions and BSS definitions use the source order that
this mode emits in reverse. This reproduces both the retail function order
and every named BSS offset. The constructor-first reference source supports
this emission model independently of the function's score; no exceptional
compiler version or per-function flags are involved.

Deferred emission also makes the complete buffer definitions available when
MWCC generates code. It can then produce its own shared BSS base. Earlier
experiments appeared to require private linkage, but declaring the arrays
before code generation was the relevant change; their existing external
linkage is retained. The final source contains no explicit pooled-base symbol
or synthetic record overlay.

## Why the earlier loop rewrites stalled

The previous LLDB capture showed post-unrolling address propagation rejecting
the stride-three search updates while they carried `gTransientMapBits` as a
known global symbol. Pointer loads or stack-based pointer views could remove
that association and fold the updates, but introduced other instructions or
data. They were diagnostic experiments, not acceptable source fixes.

With the real globals and deferred emission, MWCC generates the shared base
itself. The inlined search now has retail's load displacements `0/1`, `3/4`,
`6/7`, `9/10`, and `12/13`, followed by one advance of 15. The ordinary indexed
allocator also receives the retail registers. The standalone search retains
its distinct, already-exact instruction sequence.

## Validation

All 54 emitted function bodies have the same raw instruction bytes as the
retail object. Section sizes and alignments, named function/data offsets, and
the initialized data bytes are preserved. The strict source-linked DOL
checksum verifies the resolved relocations, including the compiler-generated
BSS base and anonymous literals that objdiff normalizes.

The final LLDB capture validates all 264 setter instructions across 17 stages
and replays 71 register-color choices, with zero retail differences. Ordinary,
instrumented, and formatted objects have the same SHA-256:
`e23fe05d483dcfa4e6687958447da8c29a995ae2ac2b47f2c1e448d6115ecc8c`.

```sh
python3 tools/unitfuzzy.py dlls/engine/23/23.c
python3 tools/tricky_backend_trace.py --unit main/dlls/engine/23/23 \
  --function SaveGame_gplaySetObjGroupStatus --graph \
  --output build/flag_probe/savegame_complete_backend
python3 configure.py --matching
# Each Ninja invocation must have a 30-second timeout.
ninja all_source
ninja
clang-format --dry-run --Werror src/dlls/engine/23/23.c include/main/dll/savegame.h
```

The source-only changes affect the setter, transient helpers, standalone
search wrapper, and initializer; the other function bodies are unchanged
apart from their source order. The generated DLL path and TU boundaries are
unchanged.

## Live state and checkpoint recovery (2026-10-06)

`savegame_state.h` now owns the actual live-state definition, checkpoint
record, saved positions, and timer entries. `gSaveGameState` replaces the raw
0xF70-byte buffer in the same BSS position. The work buffer and restart
checkpoint use `SaveGameData*`; the latter was previously a `u32`, truncating
heap pointers on a 64-bit native build. Indexed accesses replace shifted
whole-record casts and integer pointer arithmetic throughout the state,
timer, and saved-position operations, including the two direct curve/title
consumers. Unrelated save-options/high-score storage remains outside this
recovery.

The layout follows SFA's allocation and copy boundaries:

| Record | Size | Evidence |
| --- | ---: | --- |
| `SaveGameData` | 0x6EC | Restart allocation and full checkpoint copies |
| `SaveGameRuntimeState` | 0x884 | Contiguous tail cleared when loading a map |
| `SaveGameState` | 0xF70 | Retail live allocation and neighboring BSS boundary |
| `SaveGameTimeEntry` | 8 | Object ID and expiry-time loads/stores |

`main/mm.c` allocates 0x6EC bytes for the PAL work buffer and 0x6ED for
EN/JP, where the final byte belongs to the separately addressed progressive
scan flag. That byte is not part of `SaveGameData`. Save-point flag 2 locks
updates via the byte at 0x22; flag 4 unlocks it. The independently zeroed
byte at 0x23 remains unnamed.

Retail `SaveGame_gplayAddTime` caps the timer count at 256. The former array
size of 272 came only from filling the gap to the next global. The recovered
runtime record contains 256 entries and an opaque 0x80-byte tail. Dinosaur
Planet's `engine/29_gplay` independently has typed save/runtime state,
`Savegame* sRestartSave`, and `MAX_TIMESAVES 256`; its different layout is
not copied into SFA. Foxhollow's native port also provided a useful example
of typed saved-position writes.

### Preserved retail overrun

After removing a saved position, `saveGame_unsaveObjectPos` writes zero at
live-state base + 0x20158. This is not a dirty flag inside the allocation.
All five retail bodies load the live-state base, add `0x20000`, and store
at displacement `0x158`. In every version the write falls inside the
separate `dataCurveTable` at offset 0x3188:

| Version | Live-state base | Overrun destination |
| --- | --- | --- |
| EN v1.0 | 0x803A32A8 | 0x803C3400 |
| EN v1.1 | 0x803A3F08 | 0x803C4060 |
| JP | 0x803A33C8 | 0x803C3520 |
| PAL v1.0 | 0x803A4A48 | 0x803C4BA0 |
| PAL v1.1 | 0x803A4C08 | 0x803C4D60 |

The explicit byte-offset access and allocation-backed size assertions
preserve and expose this retail bug. The native checkpoint/timer test does
not exercise object-position removal or claim the whole TU is portable.

### Recovery validation

Every input DOL was verified against its configured SHA-1. The complete
save-game unit and changed curve/title consumers match 100% in all five
versions: EN/JP have 54 save-game functions, 8,308 code bytes, and 5,524 data
bytes; PAL has 55 functions, 8,240 code bytes, and 5,532 data bytes. Every
version passes `ninja all_source` and the strict source-linked DOL checksum,
with no retail-object substitution. Compiler profiles, TU boundaries, and
matching classifications are unchanged.

Full-project objdiff reports were regenerated without completion overrides.
They retain only the existing TRK exception-vector carving and MusyX
`sal_volume` discarded exception-data report discrepancies; the linked DOLs
are exact. Formatting preserves each region's raw save-game object hash.

`python3 tools/test_savegame_state.py` compiles the actual record definitions
and checkpoint/timer function bodies with 64-bit pointers at `-O0` and `-O2`
under ASan/UBSan. It checks allocation failure, checkpoint reuse and release,
health restoration, character selection, partial-copy boundaries, save-point
locking, timer replacement, equality at expiry, tail replacement, capacity,
and the opaque runtime tail.
