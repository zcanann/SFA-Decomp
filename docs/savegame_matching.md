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
