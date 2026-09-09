# Retail registry audit

`python3 tools/orig/resource_registry_audit.py GSAE01_rev1` compares EN's
resource identities with the same slots in a second verified retail DOL.
`--slots 356,358,359,380,381,382,383 --json` provides detailed evidence for a
selected neighborhood. `--all` includes entries without discrepancies.

The tool reads the real `gResourceDescriptors` pointers, checks current symbol
addresses and split owners, and compares available words using independently
matched function pointers. Other words are compared literally. Changed or unresolved
callbacks remain reported as unresolved; equal slot numbers alone do not prove
an interface. Comparisons stop before the next distinct registered address.
That limit is evidence for further investigation, not an inferred TU boundary.
The tool does not change configs or claim matches.

All four available verified images contain 706 registry words, including two
null entries. Comparing EN with itself checks all 704 non-null records with
no discrepancies, including functionless records in `.sdata`. The regional
reports distinguish real callback changes from missing names and wrong offsets.
PAL rev0 remains unavailable because the local artifact fails its configured
retail hash.

The timer investigation exposed this concrete EN rev1 / PAL rev1 data corridor:

| Slot | Resource | EN rev1 registry pointer | PAL rev1 registry pointer |
| --- | --- | --- | --- |
| 356 | CFLevelControl | `80323C88` | `803249C8` |
| 358 | Exploded | `80323CC0` | `80324A00` |
| 359 | SpiritDoorLock | `80323D00` | `80324A40` |
| 380 | GCRobotPatr null record | `80323D38` | `80324A78` |
| 381 | RollingBarrel | `80323D68` | `80324AA8` |
| 382 | MMPLevelControl | `80323DA0` | `80324AE0` |
| 383 | MoonSeedBush | `80323DD8` | `80324B18` |

At the time of this audit, the regional Exploded symbol starts four bytes too
early, the null-record symbol eight bytes too late, and MMPLevelControl four
bytes too late. The other canonical descriptor names are missing. The retail
pointer targets agree with all compared EN scalar words and independently
matched callbacks. The Exploded comparison covers 64 bytes; EN and JP allocate
80 bytes before the next registered descriptor. The omitted 16 bytes are zero
in EN/JP. Extending the EN symbol size into the later versions would consume
the beginning of SpiritDoorLock's descriptor.

These are config/split defects alongside a real regional tail-size difference,
not evidence that the whole regional registry needs different C initializers.
Correct the owning units and neighboring ranges before changing matching
manifests. Preserve both slots, including the functionless slot 380, and review
the descriptor-plus-tail source representation rather than widening callback
counts to explain zeros.

Other missing registry identities include RomCurve in both later versions,
ObjSeq in PAL and OptionsScreen in PAL. RomCurve's 44 and ObjSeq's 35 compared
callbacks are independently matched. OptionsScreen has one unresolved regional
callback and needs a separate code review; the audit does not call it exact.
The current modelEngine matched-data deficit also includes other symbols, so
repairing this corridor alone is not proof that the whole TU will match.

## Exploded corridor repair

The seven data ranges above now follow their retail pointers in EN rev1 and
PAL rev1. CFLevelControl's preceding 48-byte reset-bit table is byte-identical
to EN. Every descriptor word is either the same scalar or a corresponding
independently matched function pointer; the functionless slot retains all
48 bytes of its existing record. No numbered slot or text boundary moved.

Exploded now declares eleven callbacks plus opaque tail words, with total
sizes asserted as 80 bytes for EN/JP and 64 for the two later revisions.
`Resource_Acquire` returns the interface at descriptor offset `0x18`; the
spawning object's `getPhase` at interface offset `0x20` therefore reaches the
final advertised callback at descriptor offset `0x38`. No consumer of the
opaque tail was found. Resolving the compiled descriptor's relocations against
each verified DOL reproduces its complete retail bytes.

The existing projector preserves the corrected symbols and reproduces all
seven corrected ranges, stabilizing in two passes without a tooling change.
Its unrelated symbol-name/metadata normalizations were not retained. Existing
symbol fallback mappings are unchanged. Whole source objects remain identical
in EN/JP; in the later revisions only Exploded's data section and symbol shrink
by 16 bytes. Every function body and other allocated section remains unchanged.

Each later revision gains seven fully exact units and 440 matched data bytes.
This repairs ownership and the source tail; it does not reconstruct new code.
All four source builds and full reports pass, with no match regressions, and
the strict EN retail checksum passes.
