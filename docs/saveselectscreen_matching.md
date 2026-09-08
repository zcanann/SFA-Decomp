# Save-selection screen matching

Verified for EN v1.0 (`GSAE01`) on 2026-09-07. Engine slot 53 remains at
`src/dlls/engine/53/53.c`, using its existing common GC/1.3 compiler and optimization profile.

`SaveSelectScreen_render` now indexes `gSaveSelectInfoTextIds` with a byte-sized starting
index plus the task-text index. The starting index is three minus the number of visible
task texts, preserving the previous byte conversion and the bottom-aligned text selection.
Replacing the advancing pointer with this indexed access restores retail's register
allocation in both text loops without changing control flow or compiler flags.

| Measure | Before | After |
|---|---:|---:|
| `SaveSelectScreen_render` fuzzy match | 99.52869% | 100% |
| TU fuzzy match | 99.93009% | 100% |
| Exact functions | 14 / 15 | 15 / 15 |
| Exact code bytes | 5,604 / 6,580 | 6,580 / 6,580 |
| Exact data bytes | 1,176 / 1,176 | 1,176 / 1,176 |

The first source link exposed a separate retention issue: the object contained the correct
56-byte `.sdata` section, but the linker discarded `lbl_803DBA00`. Retail retains this
unreferenced zero word between `gSaveSelectInfoStartSlot` and `gSaveSelectTextureIds`.
Dropping it moved the following texture IDs and format strings four bytes earlier, causing
40 differing DOL bytes despite the exact objdiff report. Adding the existing symbol to
`force_active` restores the complete retail layout.

The previous `.data` alignment override is unnecessary and has been removed. The compiler's
natural eight-byte alignment produces the same linked DOL as the four-byte override; `.sdata`
already used eight-byte alignment in both cases. Symbol retention, rather than alignment,
accounts for the missing word.

Validation passes: `python3 configure.py --matching`, `ninja all_source`, and strict `ninja`
with the TU linked from C and the unchanged retail checksum. Clang-format leaves the source
and its public headers unchanged; their dry-run checks pass and the object hash is preserved.
