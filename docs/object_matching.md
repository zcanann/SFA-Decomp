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
