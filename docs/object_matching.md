# Object loader helper recovery

Target: EN v1.0 (`GSAE01`), common game compiler GC/1.3.

Two called private helpers account for the early literals in `object.c`:

- `objPlacementRangeToWorld` converts the placement record's range units to
  world units by multiplying by eight. Both load-distance fields use it.
  Its emitted body introduces the signed conversion bias at pool offset 0x28.
- `objInitCullScale` scans non-null model banks for the maximum cull distance,
  starting at 10, applies the object's optional byte scale divided by 255,
  and stores the existing `hitboxScale` field. Its emitted body introduces
  10 and 255 before `modelInitBones` introduces 0.01 and 0.1.

The helper names and source decomposition are inferred from these operations
and the retail pool order. All three calls inline under the existing compiler
profile. The linker discards both out-of-line bodies while retaining their
shared literals. No unused seed functions, explicit pool definitions, compiler
exceptions, or split changes are needed.

The complete 84-byte source pool matches the retail content. The carved retail
object additionally includes four trailing alignment bytes. An isolated link
substituting the compiled object reproduces every allocated data section,
including the entire 40,744-byte linked `.sdata2` section. Both extra helper
bodies are absent from that link; every retail function retains its size.

The only linked differences are 26 bytes in `loadCharacter`. Its parent pointer
and load flags occupy r29/r28 instead of retail r28/r29. Helper extraction fixes
the model-pointer allocation in the culling loop and improves this function
from 99.77795% to 99.80858%; the other 59 functions remain exact. The TU's fuzzy
code score improves from 99.9674% to 99.9719%. It remains `NonMatching` until
that register exchange is resolved.

Validation: objdiff, isolated full-section link comparison, formatting with an
unchanged raw object, `ninja all_source`, and the strict matching DOL checksum.

## GC/1.3 allocator trace

The remaining exchange is reproducible under LLDB using the compiler backend
capture tool. The instrumented and ordinary objects have identical SHA-256
`f6bff8a34073cbfff90a6e30a4f42d15fd1a5f3f25f2e4eabe9777cd7c7a8990`.
This observation applies to the source at `db7dce19e3`, not every subsequent
revision; virtual register numbers are capture-specific.

```sh
python3 tools/tricky_backend_trace.py --unit main/main/object \
  --function loadCharacter --graph \
  --output build/flag_probe/object_loader_backend
python3 tools/tricky_backend_trace.py \
  --read build/flag_probe/object_loader_backend/trace.json \
  --function loadCharacter --register 36 --register 50
```

The capture aligns all 653 instructions across 19 recorded stages and validates
both graph simplification and physical coloring. It reports 21 differing
instructions, all explained by the parent/flags exchange. The coloring prefix
is object (virtual 44, r31), model definition (54, r30), parent (36, r29), then
model flags (50, r28).

The distinction arises before physical coloring:

| Value | Removal kind | Degree at removal | Low-degree threshold | Weight |
| --- | --- | ---: | ---: | ---: |
| Model flags, virtual 50 | Low-degree sweep | 27 | <29 | 68 |
| Parent, virtual 36 | High-degree selection | 37 | <29 | 3 |

The flags' remaining active virtual neighbors are only the parent, object, and
model definition. The parent has additional fixed-color neighbors from calls
before and after the flags' live range. In particular, several distinct nodes
already occupying r3 or r4 contribute separately to simplification's degree,
although they block only one physical register each during coloring. Removal
order is reversed for coloring, giving the parent first choice of r29. The
trace tool now reports each requested register's removal degree and groups its
fixed-color neighbors, so this distinction can be inspected without another
ad hoc replay script. These are compiler heuristic weights, not runtime counts.

Read-only comparison with `../dinosaur-planet/src/object.c` finds the related
`objSetupObjectActual` loader, including model-flag acquisition, DLL-state,
event-data, weapon-data, and visibility-radius helpers. That lineage supports
investigating helper boundaries, but is not proof of the EN GameCube source.
Extracting those stages individually and in combinations did not resolve the
exchange. Local lifetime reuse, declaration order, and equivalent callback
access forms also did not improve the baseline. Regressing experiments were
removed. Isolated compiler-version comparisons likewise did not supply a
match; the active game compiler remains GC/1.3.

## Typed loader interface

`loadCharacter` now accepts the canonical `ObjPlacement` record and `GameObject`
parent and returns `GameObject*`. The record's first signed halfword supplies
the sequence/object ID; its position, range, and map-act fields supply the
remaining placement reads. The map-layer and object-index parameter names
follow their existing callers and stores. Keep the explicit `s16*` conversions
at `ObjAnimComponent.placementData` and the legacy sizing API: this recovery
does not change that shared storage contract.

The loader reads its callbacks through `ObjectInterface` instead of anonymous
byte offsets. The local `getModelLoadFlags` name describes how this loader uses
the legacy `getObjectTypeId` slot. Its cast preserves the object argument; the
extra-size call retains both object and cursor arguments, matching the retail
call site rather than narrowing it to the generic table's no-argument typedef.
All direct callers were audited, including the queued request in `gameloop.c`.

A new LLDB capture of this recovery produces the same raw object hash recorded
above. Direct comparison of both initial and colored graphs finds all 331
nodes' neighbor lists, weights, degrees, colors, and flags unchanged. The
instruction-role comparator independently maps 267 registers with no partition
conflicts or mapped edge differences; its 48 unmapped graph neighbors are
covered by that complete node comparison. Thus the typed interface improves
source recovery but does not explain or resolve the remaining allocation
exchange. Further tests of return paths, model-call temporaries, loop indices,
allocation signedness, and flag-expression forms produced no code-match gain.
