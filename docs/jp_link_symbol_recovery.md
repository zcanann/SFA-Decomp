# JP link symbols and checkpoint pool

The first full JP retail-object link failed on five duplicate global names.
Four were stale EN constant identities in checkpoint storage; the fifth exposed
a static SDK callback globally. Correcting the annotations allows the extracted
objects to reproduce the retail DOL, and exposes a checkpoint pool boundary that
was previously blocked by the misleading semantic names.

## Constant identities

Retail r2-relative loads distinguish the two sets of storage directly:

| Stale checkpoint name | JP checkpoint address/value | Actual JP curve constant |
| --- | --- | --- |
| `gFloatNegOne` | `803E0630`: `BC23D70A` (-0.01f) | `803E0750`: -1.0f |
| `gFloatOne` | `803E0634`: `3C23D70A` (0.01f) | `803E0754`: 1.0f |
| `gFloatZero` | `803E0638`: `3F7FBE77` (0.999f) | `803E0758`: 0.0f |
| `gFloatHalf` | `803E0658`: `C0800000` (-4.0f) | `803E0778`: 0.5f |

`Checkpoint_getRouteHeading` consumes the first three checkpoint values;
`Checkpoint_findRouteForObject` also reads the latter two. The separate
`Hcurves_romcurve` consumers use the curve constants. The checkpoint records
return to regional address labels, while the correct curve names are retained.
Neither a shared name nor the same numeric address in another version establishes
identity. No literal declarations are added to source.

The complete EN checkpoint constant pool at `803E04D8..803E053C` and JP pool at
`803E05F8..803E065C` have identical 100-byte contents. Both have a separate
four-byte zero alignment gap before the following screen-transition pool. The
JP claim previously included that gap, and its last four-byte -4.0f literal was
incorrectly sized as eight bytes. Removing the false semantic names lets the
existing projector recover the correct range and canonical names for the first
three pool entries. No TU is split or reordered.

## Reset callback linkage

OSMemory's `OnReset` at `802442F4` is the source's static reset callback. Its only
aligned data reference is the owning reset record at `8032D928`. CARDBios has a
different `OnReset` at `8025F06C`, referenced by its record at `8032ECE0`.
OSMemory's callback is now local, agreeing with its source and EN configuration;
the card callback keeps its existing linkage.

## Validation

JP's checkpoint unit (`dlls/engine/3/3.c`) now matches all 18 functions, 8,248 code
bytes and 1,884 data bytes. It gains 100 matched data bytes. Removing alignment
padding reduces the report's total-data denominator by four bytes; matched-code
and total-code counts are unchanged. The matching manifest now includes the unit.
All 988 JP source objects remain byte-identical. The corrected pool, callback
scope and all split ranges survive regeneration.

The all-retail JP link and a link substituting checkpoint, OSMemory, GXFrameBuf,
GXLight and GXTexture source objects both reproduce SHA-1
`a0646def31229c051f5143e6551840e6560b0556`. JP's source build and EN's source build
and strict checksum pass. Compiler settings and C/C++ source are unchanged.

A broader diagnostic substitution of all 947 previously credited JP source units
still fails on unresolved regional symbols, including `aramInitStreamBuffers`
and externally declared object constant pools. The linker reports 60 distinct
missing names before its error limit. This is a separate remaining recovery task;
passing the five-unit check does not establish a complete JP source link.

```sh
python3 tools/retail_pool_audit.py -v GSAJ01 dlls/engine/3/3.c dlls/engine/20_Hcurves/Hcurves_romcurve.c --json
python3 tools/verify_source_link.py GSAJ01 dlls/engine/3/3.c dolphin/os/OSMemory.c dolphin/gx/GXFrameBuf.c dolphin/gx/GXLight.c dolphin/gx/GXTexture.c
```
