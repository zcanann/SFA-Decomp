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

`loadCharacter` is now byte-exact as well, so all 60 functions and the
complete pool match and the unit is `MatchingFor("GSAE01")` at 100%. Helper
extraction had already raised it from 99.77795% to 99.80858%; recovering two
local lifetimes closes the remaining parent/load-flags register exchange
described below.

Validation: objdiff, isolated full-section link comparison, formatting with an
unchanged raw object, `ninja all_source`, and the strict matching DOL checksum.

## GC/1.3 allocator trace

This section records how the exchange was diagnosed while it was still open; it
is the mechanism the closing edit had to defeat. It was reproducible under LLDB
using the compiler backend capture tool. The instrumented and ordinary objects have identical SHA-256
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
exchange. Declaration order and equivalent callback access forms did not improve
the baseline either, and single-site lifetime reuse was tried without success;
what finally worked was reusing two lifetimes at once, since the change is
all-or-nothing. Regressing experiments were removed. Isolated compiler-version
comparisons likewise did not supply a match; the active game compiler remains
GC/1.3.

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
covered by that complete node comparison. Thus the typed interface improved
source recovery without explaining the allocation exchange, which the local
lifetimes below account for. Further tests of return paths, model-call
temporaries, loop indices, allocation signedness, and flag-expression forms
produced no code-match gain.

## Trailing constant-pool alignment

The `.sdata2` claim now ends at the actual 84-byte pool, leaving the following
four zero bytes as an automatic alignment gap before `objanim.c`. The former
four-byte anonymous float symbol at that gap is removed. The next unit's start
and eight-byte alignment remain unchanged; no source constant or padding array
is added.

| Version | Object pool start | Pool end / gap start | Next unit start |
| --- | --- | --- | --- |
| EN | `803DE888` | `803DE8DC` | `803DE8E0` |
| EN rev1 | `803DF508` | `803DF55C` | `803DF560` |
| JP | `803DE9A8` | `803DE9FC` | `803DEA00` |
| PAL rev1 | `803E0250` | `803E02A4` | `803E02A8` |

Each configured DOL hash is verified. The complete 88-byte retail windows are
identical across these versions, and the first 84 bytes equal each compiled
source pool. `tools/retail_pool_audit.py src/main/object.c --version <version>`
finds 41 direct loads in each version, all ending at or before the new boundary,
with no outside direct-load consumers. The EN assembly before recarving contains
the trailing symbol's definition and no references to it. This access audit is limited to the
supported direct loads; the source and isolated-link checks supply independent
layout evidence.

An EN link substituting the current compiled object preserves every allocated
data section, including the entire linked `.sdata2`. At the time of the boundary
repair its only differences were the 26 text bytes in `loadCharacter` described
above; those are now gone too. Repeating that substitution after the boundary
repair preserves every allocated section of the preceding diagnostic link,
including text.

The secondary split claims are refreshed with `version_progress.py --write`;
only this pool end changes in each version. All source objects remain
byte-identical, as do every retail function and relocation in the recarved
object. Objdiff now reports this pool as 100%, adding 84 matched data bytes per
version while removing four alignment bytes from its total. Other units and
function scores are unchanged. All four `all_source` builds and the strict EN
checksum pass.

## Local lifetimes close the register exchange

The parent/load-flags exchange was not a coloring wall and not reachable by any
ordering knob. It was two reconstructed locals that retail did not have.

The reconstruction declared `total` for the running model-data offset and walked
the arena with a separate `cursor`. Retail used **one** local for both: the same
int accumulates each model's data offset into `offsets[]` before allocation and
then walks the object's trailing region afterwards. Deleting `total` and using
`cursor` in the model-load loops is the first half.

The reconstruction also advanced the arena in place across the DLL-state block
(`cursor += dllStateSize`). Retail computed the block's end in a second int and
copied it back, exactly the idiom the weapon-DA block below it already uses, and
it reused the dead `base` local rather than a fresh one:

```c
    if (dllStateSize != 0) {
        obj->extra = (void*)cursor;
        base = cursor + dllStateSize;
    } else {
        obj->extra = NULL;
        base = cursor;
    }
    cursor = base;
```

Neither edit helps on its own. Alone, the merged accumulator leaves the 21
positional differences untouched and the DLL-block copy trades them for 22 of
its own. Together they are byte-exact. That all-or-nothing behaviour matches the
copy-survival class in [source shape levers](source_shape_levers.md): the web
count the allocator sees is what moves, so a partial change just relocates the
damage.

The backend capture explains why the earlier sweeps could not find this. The
exchange was decided before physical coloring, in simplification: load flags left
by the low-degree sweep at degree 27 while the parent went out through
high-degree selection at degree 37, reversing their order for coloring and giving
the parent first choice of r29. Degree is a property of how many webs exist and
overlap, and declaration order cannot change that. Merging two locals into one
and redirecting a join through a dead local does.

The prior exhaustive declaration sweep (all 31 declarations across roughly 32
positions, about 960 gated builds, every one flat) was therefore measuring a knob
that could not reach the defect, not proving the function unmatchable. The band
is 12 GPRs wide, far past the width-4 cliff where ordering knobs stop working;
at that width the productive move is to question the **set** of source locals
rather than their order.

Both other versions tested improve under the same source, which is what a real
source recovery should do rather than an EN-specific spelling: `GSAJ01` and
`GSAE01_rev1` each rise from 99.74753% to 99.77558%.
