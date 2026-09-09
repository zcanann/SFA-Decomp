# MSL float trigonometry initialization

## Retail evidence

EN `trigf.c` contains `tanf`, `cos(float)`, `sin(float)`, `cosf`, `sinf`,
and a 48-byte initialization function at `0x80294B88`. The two float overloads
have native MWCC C++ manglings, `cos__Ff` and `sin__Ff`. The adjacent
`hyperbolicsf.c` function is likewise `fabsf__Ff`, not the C-linkage `fabsf`
implemented elsewhere in the math library.

The initializer loads four floats from the TU's 16-byte read-only table and
stores them into its 16-byte writable reduction table. A constructor entry at
`0x802C1884` points to this function. These are independent reasons to test C++
language mode, not an inference from an aggregate compiler score.

## Recovery

Compile `trigf.c` as C++ with its existing GC/1.2.5 compiler, and
`hyperbolicsf.c` as C++ with its existing GC/1.2.5n compiler. Neither changes the
game's GC/1.3 baseline. Declare the float overloads normally, with C linkage
retained for the C math API and the shared coefficient tables.

Initializing the writable array from the four elements of `tmp_float` makes
MWCC emit the exact retail initializer and constructor relocation. Remove both
the hand-written `__sinit_trigf_c` body and its forced-section registration.
Keep the compiler-generated function local in the symbol configuration.

The common table header also corrects the previous `extern const float[]`
declarations to agree with the actual writable definitions. The exponential
consumer is unchanged at the object-byte level. The recovered spelling of the
initialization is supported by generated code and layout; no original header or
source artifact establishes that it is the literal historical spelling.

## Verification

- All six trig functions and the adjacent float absolute-value function remain
  100% in objdiff.
- All allocated section layouts and bytes are unchanged: trig `.text` 1004,
  `.ctors` 4, `.rodata` 16, `.data` 16, `.sdata2` 24 bytes.
- The constructor relocation is unchanged. Literal relocations retain their
  section offsets but receive new anonymous compiler symbol numbers.
- The constructor becomes local and its former named registration object is
  absent, as expected for generated initialization. Objdiff 3.5.1 consequently
  leaves the four unnamed `.ctors` bytes unscored (56/60 data bytes reported),
  even though the section and relocation are identical. No synthetic source
  symbol is added to conceal that reporting limitation.
- `python configure.py --matching`, `ninja all_source`, and strict `ninja` pass.
  The retail DOL SHA-1 remains `e750e8e894707a52446118a4b84f1b58b677b269`.

Formatting is checked separately from source recovery, with raw object hashes
compared before and after formatting.

## Cross-version completion (2026-09-08)

The same recovered source is now marked matching for EN rev1, JP and PAL rev1.
The automatic matching manifest had omitted it because objdiff leaves the
unnamed four-byte constructor entry unscored. The explicit `MatchingFor` list
records the independently checked exception and survives manifest regeneration.
PAL rev0 remains excluded: its local artifact fails its configured retail hash.

| Version | Constructor entry | Generated initializer |
| --- | --- | --- |
| EN | `802C1884` | `80294B88` |
| EN rev1 | `802C2004` | `802952E8` |
| JP | `802C1984` | `80294C78` |
| PAL rev1 | `802C2204` | `802954F8` |

Each hash-verified DOL stores the listed initializer address in the listed
constructor entry. Source and extracted objects have identical bytes, sizes
and alignment for all five allocated sections: 1004 text bytes and 60 data
bytes. The constructor relocation is the same `R_PPC_ADDR32` reference to
text offset 956, with zero addend. The source object's writable flag on
`.sdata2` differs from the extraction's flag, as it already does in matching EN;
this is not an additional regional difference.

The three regional symbol configs now mark the compiler-generated initializer
local, agreeing with EN and MWCC. A scan of their extracted object relocations
finds only the owning constructor entry referencing this symbol; no external
consumer depends on global linkage. The synthetic reference label remains an
extraction annotation and is not added to source.

Full source builds and source-object hash comparisons pass for all four
versions. Fresh objdiff reports preserve the six exact functions and 56 scored
data bytes; only the three secondary targets gain completion credit (1004 code
bytes and 60 data bytes each). EN remains unchanged and passes its strict
retail checksum. Secondary targets currently support progress reports only;
`configure.py` rejects their `--matching` mode, so no secondary full-link
checksum claim is made.
