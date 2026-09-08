# Object DLL matching milestone

EN v1.0 (`GSAE01`), 2026-09-07.

All 527 configured translation units under `dlls/objects/` match and link from C.

| Measure | Matched | Total |
| --- | ---: | ---: |
| Object DLL units | 527 | 527 |
| Functions | 5,249 | 5,249 |
| Retail text bytes | 1,266,408 | 1,266,408 |
| Assigned data bytes | 104,100 | 104,100 |

The complete objdiff report has no nonmatching object unit. The matching ELF's
link inputs independently contain 527 compiled object-DLL objects and no retail
object-DLL substitutes. Both `ninja all_source` and the strict retail DOL checksum
pass. This milestone covers the configured object DLLs in the active EN target;
other game categories and unassigned automatic gaps are separate work.

The final recoveries were [Baby CloudRunner](BabyCloudRunner_matching.md),
[Scarab](Scarab_matching.md), and [the mounted CloudRunner's radius storage](ui_mount_data_ownership.md).
