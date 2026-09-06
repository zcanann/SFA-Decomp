# MSL exponential tables

## Recovered ownership

EN `powf` at `0x80294BB8` uses a 129-element log2 mantissa table, then a
nine-coefficient exp2 polynomial. The former index is the top seven fraction
bits plus a possible rounding increment, proving the range 0..128. The latter
is consumed as a ninth-degree polynomial in the fractional exponent, with a
separate constant term of one.

The table at `0x80332C78` contains `log2(1 + index/128) - 0.375`, rounded to
float. The polynomial starts at `0x80332E7C`. Defining these as separate mutable
float arrays lets MWCC select a common `.data` base itself: the old manually
passed, cast integer-blob pointer is unnecessary. Decimal literals round to the
original words, and all 584 data bytes retain their order. The final eight
unaccessed words at `0x80332EA0` remain opaque `sUnusedMathData`; their values
alone do not establish the missing consumer or source declaration.

The two floats at `0x803DC650` are the high/low parts of `log2(e) - 1`, used in
the mantissa correction polynomial. Only this TU consumes them. Recover their
definition here, extending its `.sdata` ownership by eight bytes. The normal
small-data threshold handles the sized array, replacing both the forced-section
extern and the TU's `-sdata 0` override. The redundant C++ language toggles around
the automatic coefficient-array initializer are also unnecessary.

## MSL special values

The preceding two words at `0x803DC648` and `0x803DC64C` are `0x7FFFFFFF` and
`0x7F800000`, used for NaN and infinity through address-based float loads.
They match the existing MSL `float.c` definitions and standard `NAN`/`HUGE_VALF`
access idiom in this repository and contemporary reference projects. Activate
that data-only source with the existing GC/1.2.5n MSL compiler, name both symbols
accordingly, and use the canonical math header in `powf`.

The definitions use the MSL word-array representation, with explicit one-word
bounds. GC/1.2.5n puts inferred-size definitions or definitions following the
header's incomplete-array declarations in `.data`, not the evidenced `.sdata`.
This dependency-free data TU therefore does not import those incomplete
declarations. Consumers retain the incomplete declarations and their original
address-based access. No forced section or synthetic float literal is involved.

## Verification and remaining work

- `powf` instruction bytes are unchanged: 479 instructions, 99.78079% objdiff,
  with twelve operand differences in the three inlined log2 paths.
- Its complete 624-byte data ownership now matches, including the newly owned
  eight-byte correction pair. Relocations to the new table symbols and local
  data-section base resolve to the same retail addresses.
- The eight-byte MSL `float.c` unit is fully matching and linked from source.
- `all_source` and the strict DOL checksum pass. No compiler version changes.

The pre-existing `sconst_type` section pragma for the automatic local
coefficient-array template is still unresolved. Removing it preserves every
instruction byte but moves that template to `.sdata2`; C++ mode and older
GC/1.1/1.2.5 do not independently recover the retail placement. This cleanup
does not claim to have solved that remaining source-layout problem or the
per-function optimization pragmas.
