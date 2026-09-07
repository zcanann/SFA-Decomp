# Modgfx DLL 152: complete EN match

`src/dlls/modgfx/152/152.c` now matches EN GSAE01 completely and links from
source. The strict retail DOL checksum passes.

| Measure | Before | Complete |
| --- | ---: | ---: |
| Unit fuzzy match | 99.770996% | 100% |
| Exact functions | 2 / 3 | 3 / 3 |
| Exact code bytes | 8 / 1,048 | 1,048 / 1,048 |
| Exact data bytes | 624 / 624 | 624 / 624 |

## Recovering the resource arrays

The old `Dll98EffectResourceView` overlaid one packed word array. Its common
register base had been mistaken for a source struct. The resource now has
separate definitions for the two 18-vertex meshes, 16 triangles, 18 vertex
indices, and seven sequence parameters. The vertex and triangle counts come
from the retail spawn call; the sequence copy establishes its seven entries.
The vertices use the shared ten-byte `ModgfxEffectVertex` definition.

The two unaccessed 20-byte spans remain opaque byte arrays in their original
positions. The two bytes after the sequence parameters are ordinary alignment
padding before the descriptor, rather than a fabricated state field. The
descriptor remains at the end of the TU.

All data definitions precede the functions and retain their retail order.
MWCC generates `...data.0` and the shared register base itself. The source
accesses the arrays directly, with no resource overlay or pointer/integer
laundering. The generated DLL path, TU boundaries, GC/1.3 compiler, and existing
`nopeephole,noschedule` optimization profile are unchanged.

## Why the reload returns

The only old instruction mismatch followed the random duration assignment:
retail used `lha r0,534(r31)`, while the reconstructed source emitted
`extsh r0,r0` by forwarding the preceding store.

LLDB captures locate that replacement in value numbering. The old explicit
blob pointer acquires a precise memory identity during alias propagation.
With the separate arrays, MWCC's generated pooled base carries the broad
memory identity through that pass, and value numbering retains the load.
Subsequent address propagation folds the array offsets into the exact retail
displacements. The ordinary assignment
`gDll98SequenceParams[2] = gDll98SequenceParams[1]` now matches directly.

The earlier store-forwarding closures in the worklists described the old data
model, not a compiler limitation. This is another case where native global
definitions recover behavior that source-level emulation of a pooled base
cannot reproduce.

## Validation

All three raw function bodies match retail. The complete `.text` (1,048
bytes), `.data` (584 bytes), and `.sdata2` (40 bytes) contents match. The seven
resource symbols and descriptor have the expected section offsets and sizes;
there is no additional BSS or small-data allocation. The strict DOL checksum
also verifies the resolved pooled-base and constant relocations.

The final LLDB capture aligns all 260 spawner instructions across 16 stages
and replays 91 register-color choices with zero retail differences. Ordinary
and instrumented objects have the same SHA-256:
`1a0fdaebe379270d4fbcc5c303a48769fd15f89e42e6eda24febdf6b415f3168`.

```sh
python3 tools/unitfuzzy.py dlls/modgfx/152/152.c --all
python3 tools/tricky_backend_trace.py --unit main/dlls/modgfx/152/152 \
  --function dll_98_spawnEffect --graph \
  --output build/flag_probe/dll152_complete_backend
python3 configure.py --matching
# Each Ninja invocation must have a 30-second timeout.
ninja all_source
ninja
clang-format --dry-run --Werror src/dlls/modgfx/152/152.c \
  include/main/dll/dll_0098_modgfx.h
```
