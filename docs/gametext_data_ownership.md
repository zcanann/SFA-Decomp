# Gametext initialized-data ownership

`gameTextGet` matches all 660 retail EN bytes after restoring a separate
initialized-data input. Its C body, the complete gametext text boundary, GC/1.3,
and both units' optimization profile are unchanged. `gametext_data.c` is a
reconstructed descriptive filename, not a recovered original filename.

## Evidence

The previous merged source made MWCC pool every initialized `.data` object
under `...data.0`, starting at `gUtf8CharClassTable`. In retail, `gameTextGet`
loads its message base at `sJpDiscStatusGlyphs` (`802C8F40`), then addresses the
five diagnostics at offsets `EC4`, `ED4`, `EE0`, `EF0`, and `EFC`. It independently
loads `sMapDirectoryNameTable` at `802C729C` for both missing-text paths.

This is a pool/ownership discrepancy, not a loop or register-allocation problem.
Ordinary pointer spelling changes did not fix it. Qualifying the directory
table as `const` was rejected because it moved real writable-section storage
to `.rodata`.

GC/1.3 was traced under macOS LLDB with Wibo. The compiler SHA-256 is
`4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715`.
The frontend and backend captures establish that the pooled addressing already
exists before backend global optimization. The additional data-pool trace
observes these compiler routines:

| Compiler address | Observed role |
| --- | --- |
| `4B2F60..4B3166` | Assign an input object to an ELF section and its pool |
| `4D0260..4D0377` | Create the synthetic pool symbol at the section's first object |
| `4D0020..4D0189` | Find an eligible object's pool for code generation |

At `4B315D`, the merged source's assignments put the UTF-8 table, directory
table, and Japanese glyphs in the same pool, with section sizes before their
emission of `0`, `1025`, and `8360`. The first-object anchor stays the UTF-8
table. During `gameTextGet`, the five message literals and directory table
all resolve to that pool. The retail addresses establish a different pool
starting exactly after the SJIS table, at the Japanese glyphs. Keeping the
preceding definitions in a separate data input reproduces that boundary
without custom sections, synthetic aggregates, or per-function flags.

## Recovered ownership

| Source input | EN sections |
| --- | --- |
| `main/gametext_data.c` | `.data 802C6E98..802C8F40`; `.sdata 803DB2B0..803DB408` |
| `main/gametext.c` | Original complete text/BSS/SBSS/SDATA2 ranges; `.data 802C8F40..802C9EE8` |

The data input owns the 50 existing initialized definitions, including UTF-8
tables, directory/language tables, text windows, metrics/control/task tables,
the unexplained native data span, small-data defaults, and the SJIS lookup.
Their order, widths, values, and physical destinations are preserved. The code
input retains the resident disc-status resources and its compiler-generated
diagnostic literals and jump tables. No function moves to a different source
input. This corrects the initialized-data ownership assumed in the earlier TU
merger; it does not undo its float-pool-backed text-boundary recovery.

The three existing unreferenced words `lbl_803DB3DC`, `lbl_803DB3E4`, and
`lbl_803DB404` require explicit retail retention in `force_active`. The first
source-substitution link caught their removal even though objdiff reported
100% data matching. Retaining them makes the complete DOL byte-identical.

## Verification

- `gameTextGet`: `97.30303%` to `100%`, with a direct relocation-aware comparison
  of every instruction against the hash-verified EN DOL.
- `gameTextGetStr`, `gameTextGetPhrase`, and `gameTextMeasureString` also become
  exact. Exact functions rise from 44/54 to 48/54; no function score regresses.
- The new data object is 100% matching. Substituting it alone into the complete
  retail-object link preserves SHA-1 `e750e8e894707a52446118a4b84f1b58b677b269`.
- Resident-resource tests resolve references across both input objects and
  verify their retail bytes, pointers, and literal positions.
- All 17 gametext tests, `ninja all_source`, and the strict matching checksum
  pass. The load fixture covers 402 scenarios each at host `-O0` and `-O2`.
- The code TU remains `NonMatching`: six other functions still differ. The
  function-level relocation check does not claim that this whole TU links from
  source exactly.
- Secondary progress refreshes were attempted for JP, PAL, EN rev1, and PAL
  rev1. Their `orig/<version>/sys/main.dol` inputs are absent, so no regional
  claims or unverified regional split changes were made.

Reproduce the compiler observation with:

```sh
python3 tools/mwcc_data_pool_trace.py --output build/gametext_pool_trace
python3 tools/test_gametext_get_matching.py
python3 tools/verify_source_link.py GSAE01 main/gametext_data.c
```

The trace hooks emulate only the replaced x86 instructions and require complete
ordinary/traced object identity. They do not alter the compiler executable or
the production compilation settings.
