# ObjSeq_start matching

`ObjSeq_start` is **100% matching** in EN `GSAE01`, EN rev1, JP, PAL,
and PAL rev1. Each input DOL was verified against its configured hash before
objdiff comparison. The function remains 2,904 bytes / 726 instructions.
Resolving its source data and call relocations at the EN retail addresses
reproduces all 2,904 original DOL bytes exactly.

Two source changes resolve the previous 99.86226% result:

- Index the cast-validation array with `entries[i]` instead of advancing a
  separate pointer. MWCC derives the pointer induction variable and assigns
  the retail r26 cursor and r28 index, instead of swapping those registers.
- Cache `gObjSeqBgCmdCount` in an `s8` local before checking capacity and
  writing the first two command fields. This preserves the counter's actual
  signed-byte type and produces the retail r3 index / r0 slot conversion.
  The final field still increments the global counter once.

Compiler settings, function order, symbol layouts, and all non-text section
bytes are unchanged. Every other function retains its previous machine code.
Relocations retain their destinations, offsets, and addends; only anonymous
compiler-symbol numbering changes. The complete DLL improves from 99.76112%
to **99.77284%** and remains `NonMatching`.

Validation:

- All five regional objdiff comparisons report 100% for both `ObjSeq_start`
  and `ObjSeq_onMapSetup`.
- The reset probe passes with `--require-exact`, including the storage and ABI
  checks and its relocated EN byte comparison.
- `ninja all_source` and the strict EN checksum target pass.
- `clang-format --dry-run --Werror` passes. Running the formatter changes no
  source text and preserves the source object's SHA-256.

The source edit uses the existing language reconstruction documented in
[the map-setup investigation](objseq_map_setup_matching.md); no compiler or
optimization changes are introduced by this pass.
