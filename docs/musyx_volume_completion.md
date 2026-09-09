# MusyX volume completion across versions

`musyx/runtime/sal_volume.c` is now marked matching for EN rev1, JP and PAL
rev1 as well as EN. Its prior 96.73% data score reflects the comparison of
unlinked exception sections, not a remaining runtime-data mismatch. The
explicit `MatchingFor` list preserves this verified exception when the
conservative matching manifest is regenerated. No source, compiler profile,
section boundary or expected checksum changes.

## Retail ownership

In all four hash-verified DOLs, the exception index at `80006308` contains a
function address, size 0x798, and the exception-record address `80005A50`.
That record contains words `73080000 00000000`.

| Version | Indexed function address |
| --- | --- |
| EN | `8027F2AC` |
| EN rev1 | `8027FA10` |
| JP | `8027F39C` |
| PAL rev1 | `8027FC1C` |

Each address is the beginning of `salCalcVolume`, and each size is its complete
1944-byte body. The existing exception split therefore belongs to this TU.
PAL rev0 is excluded because the local artifact fails its configured hash.

## Why the object report leaves 20 bytes unmatched

MWCC emits standalone `CalcBus` (372 bytes) and `CalcBusDPL2` (464 bytes) ahead
of `salCalcVolume`, even though the main function inlines their calculations.
The source object consequently contains 24 bytes of `extab` and 36 bytes of
`extabindex`, covering three functions. Retail retains only the main function's
8-byte record and 12-byte index entry.

The main function's source index entry starts at offset 24 and points to its
body at text offset 836 and exception record at offset 16. Its indexed length,
record bytes and two relocation destinations match the retail entry. EN's
linked ELF has `salCalcVolume` and neither helper. Ninja's link inputs confirm
that this is the compiled source object; the resulting DOL passes the retail
checksum. Thus no exception-table source declarations or boundary changes are
needed.

Explicit inline declarations suppress the standalone helpers but change the
constant-pool order. The original declarations remain: their presence in an
unlinked object is not evidence that they survived the retail link.

## Validation

For EN, EN rev1, JP and PAL rev1, the complete `salCalcVolume` instruction bytes
match the extracted target object. All 65 live relocation records agree after
accounting for the function's source offset, normalizing defined-symbol targets
to section plus offset, and normalizing the SDK extractor's instruction-start
versus MWCC's halfword location for `R_PPC_EMB_SDA21`. This does not normalize
instruction operands. The 552-byte volume/pan table and 40-byte constant pool
match in bytes, size and alignment. The selected exception record and index
entry account for the remaining 20 bytes.

Full source builds pass for all four versions. Every source object remains
byte-identical, and fresh objdiff reports change only the three secondary
completion flags: +1944 code bytes and +612 data bytes each. The scored code
and data percentages are unchanged. EN's strict checksum passes; secondary
versions currently support progress reports only, so no full-link checksum
claim is made for them.

## PAL v1.0 and native checksum verification

The replacement PAL v1.0 DOL passes its configured hash. Its exception index
at `80006308` identifies the 1,944-byte `salCalcVolume` at `8027FAE4` and the
same eight-byte record at `80005A50`. A source link substituting this unit and
`trigf.c` reproduces the original DOL exactly, including retained exception
records after linker garbage collection. PAL v1.0 now joins the explicit
completion list. All five versions now support and pass the
[native matching checksum build](jp_source_link_retention.md), superseding the
earlier progress-only restriction.
