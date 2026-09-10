# Task-text table extent

`gameTextGetTaskText` establishes a 122-record lookup table, not the 208 records
previously declared from the gap to the next named symbol. Retail loads `0x7A`
into CTR, reads the lookup key at offset four, and advances its cursor by six
bytes. On a match it loads the text sequence ID at zero and directory ID at two.
The optional outputs are independent; failure leaves them untouched.

`TaskTextEntry` now asserts that six-byte layout and each field offset.
`GAMETEXT_TASK_TEXT_COUNT` supplies the declaration and loop bound. All 122
accessed records have directory 41 (`Sequences`) and unique object sequence IDs.
The last record is `{0x5368, 0x0029, 0x0548}`. Lookup termination is count-based;
no sentinel beyond it is accessed.

The following 516 bytes are preserved as `sGameTextUnclassifiedData`, an opaque
byte span in the same TU and physical position. The old declaration falsely
interpreted them as another 86 sequence records. Their values do not establish
a record width, sentinel, table purpose, or further boundary. No placement
attribute, artificial padding, alternate compiler profile or TU split is added.
This is a correction to the evidenced lookup extent, not a claim to have
recovered the original layout of the entire adjacent span.

| Verified retail version | Lookup function | 732-byte table | 516-byte opaque span |
| --- | --- | --- | --- |
| EN | `80015D70` | `802C8860` | `802C8B3C` |
| EN revision 1 | `80015DA8` | `802C8FE0` | `802C92BC` |
| JP | `80015D70` | `802C8960` | `802C8C3C` |
| PAL revision 1 | `80015DA8` | `802C91E0` | `802C94BC` |

Each DOL passes its configured SHA-1. The 88-byte lookup functions have equal
normalized instructions, including the explicit count, stride and field loads.
All four complete 1,248-byte spans are identical, with SHA-256
`808ab98659bfb648e1ffafa9c689877c4341b0dee6c0b2ddb30bd7440a2cf094`.
A scan for direct `lis/addi` and `lis/ori` address pairs over a 16-instruction
window finds only the lookup's reference to the table start. Aligned data-word
scans find no pointer into the span. These scans are corroboration, not proof
that an indirect consumer cannot exist; the tail remains unclassified.

All five symbol configs describe the smaller table and preserved opaque span.
PAL revision 0 gets consistent names and extents only; its locally available
DOL fails the configured checksum, so no binary validation is claimed for it.
The wiki's unsupported 208-entry claim is corrected.

All function bytes, allocated section bytes and relocation records are unchanged
in the four source objects. The only named-symbol changes are the table size
(`0x4E0` to `0x2DC`) and the adjacent private 516-byte span; every other symbol
retains its layout. The other 1,003 EN objects and 987 objects in each secondary
version remain byte-identical. Each complete objdiff report is unchanged, so
this pass claims source-structure recovery and no additional matched bytes.
The sixteen existing gametext tests pass. All four `all_source` builds and
the strict EN retail checksum pass within 30-second bounds.
