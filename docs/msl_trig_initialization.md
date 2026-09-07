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
