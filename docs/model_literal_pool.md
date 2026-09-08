# Model literal ownership

`Model_GetVertexPosition` now divides packed coordinates by `256.0f` when
header flag `0x800` is clear. The former external `gModelVertexScale` declaration
hid a constant owned by the same translation unit. Its EN retail load at
`80026EA0` reads `3B800000` from `803DE864`, exactly 1/256. The set-flag branch
still converts signed halfwords without scaling.

MWCC turns division by this power of two into the retail multiply sequence.
All 85 model function bodies remain byte-identical to their preceding compiled
versions, including the already-exact 244-byte `Model_GetVertexPosition`.
The compiler now emits the missing four-byte literal at pool offset `0x4C`.
Resolved relocation targets retain the same values; other allocated sections
and all named source-symbol layouts are unchanged. No external placeholder,
named pool anchor, section override, or compiler exception is needed.

A direct replacement with multiplication by a float literal changes scheduling
and floating-register allocation. This is the previously reported price in
`docs/priced_classes.md`; it does not apply to division by `256.0f` with the
current compiler and source.

## Alignment boundaries

The former 116-byte claim included four zero bytes at each edge. The leading
word followed `vecmath_vec3.c`'s pool and preceded the model pool's eight-byte
alignment. Its one-byte symbol had no references. The trailing word was also
unreferenced and aligned the following `object.c` pool. Both words remain in
the DOL as automatic gaps; they are no longer represented as model-owned data.

| Version | Corrected model pool | Following object pool |
| --- | --- | --- |
| EN | `803DE818..803DE884` | `803DE888` |
| EN rev1 | `803DF498..803DF504` | `803DF508` |
| JP | `803DE938..803DE9A4` | `803DE9A8` |
| PAL rev1 | `803E01E0..803E024C` | `803E0250` |

The verified retail windows are byte-identical across these four versions.
Each has 59 direct r2 loads at 23 distinct address/width pairs, all inside the
corrected span, with no incoming loads from other units. The EN assembly
reference search also finds no consumers of either removed edge symbol.
The first double is eight-byte aligned at corrected offset eight. The complete
108-byte retail span now equals the first 108 bytes of the compiled pool.
Secondary splits are refreshed with `tools/version_progress.py`; unrelated
symbol-projection differences are excluded.

## Remaining difference and verification

The scalar skinning kernels emit one additional float, 1/128 (`3C000000`), at
source pool offset `0x6C`. Retail gets that weight scale from GQR6's quantized
loads instead. The scalar reconstruction retains the constant it needs; no
storage or arithmetic workaround is introduced to manufacture an exact pool.

The `.sdata2` score improves from 95.53571% to 98.18182%. Exact code and data
byte totals are unchanged; reported model data ownership shrinks by eight
alignment bytes. The unit remains `NonMatching`. This is constant recovery and
more accurate boundaries, not a new exact function or complete unit.

Useful retail checks:

```
python3 tools/retail_pool_audit.py src/main/model.c --json
python3 tools/pool_value_sequence.py src/main/model.c
```

The latter requires `pyelftools` and still reports the three documented scalar
skinning differences. It verifies load sequences, not complete data layout.

All four `all_source` builds pass. Full objdiff reports change only the model
data span and its pool score; all function scores and other units are unchanged.
All 1,003 other EN source objects and 987 other objects per secondary target
retain their raw hashes. The strict EN retail checksum passes. Formatting
checks pass for the model source and canonical header with no formatting diff.
