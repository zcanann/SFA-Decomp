# DLL 589: inline helper recovery

The September 6, 2026 follow-up starts at `8b8a2ec4ce`. EN GSAE01
BossDrakor improves from **99.91536% to 99.95298%** with the common game
compiler, GC/1.3. The unit remains `NonMatching`.

| Function | Bytes | Before | After | Remaining instruction differences |
| --- | ---: | ---: | ---: | --- |
| `bossdrakor_updateHeadTracking` | 524 | 99.42748% | 99.580154% | Eight words: `r0` and `r4` exchanged in the neck clamp |
| `bossdrakor_update` | 2192 | 99.89051% | 99.9635% | Three words: event counter uses `r25` instead of `r30` |

All other eleven functions remain byte-identical and exact. Every remaining
instruction difference is a register operand; the former `li` versus `mr`
zero-initialization mismatch in the joint loop is resolved. The number of
differing words alone therefore does not describe the objdiff improvement.

Three small `static inline` operations give the compiler the useful local
lifetimes: resetting the neck toward its rest angle, applying shake to the
five look-at joints, and initializing the air meter. The neck helper retains
a separate upper-bound result before the outer clamp merge. The shake helper
keeps its local index before the two short angles. Its float arguments read
the scale before the amount, preserving the retail load order.

Removing the TU's `-inline off` exception enables these helpers. The existing
`nopeephole,noschedule,nocse,nopropagation` options remain. Explicit inline
helpers emit no additional function bodies: `.text` is still 6,380 bytes
with the same thirteen functions and offsets. This is a source reconstruction
supported by code generation, not proof of the original helper names.

The complete assigned data is exact: `.data` 328 bytes, `.sdata` 24 bytes,
and `.sdata2` 120 bytes. Compared with the starting object, all section
relocations and all named symbol sections, offsets, sizes, and linkage are
unchanged. The generated slot path, descriptor position, TU boundaries, and
canonical header ownership are unchanged.

The neighboring Dinosaur Planet repository's `697_BossDrakor` is useful for
encounter context, but its state machine differs substantially; it does not
provide a direct implementation of these remaining EN functions.

Reproduce the per-function measurement with:

```sh
python3 configure.py --matching
ninja build/GSAE01/src/dlls/objects/589_BossDrakor/BossDrakor.o
python3 tools/unitfuzzy.py BossDrakor.c --all
```

Both `ninja all_source` and the strict matching `ninja` pass with 30-second
timeouts. Since BossDrakor remains `NonMatching`, the strict link still uses
its retail object. The separate formatting commit must preserve the source
object byte for byte; clang-format checks cover the TU and canonical header.
