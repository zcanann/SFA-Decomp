# WORLDplanet matching progress

The September 6, 2026 pass starts at `ab4b1fe26d`. DLL 466 remains
`NonMatching`: ten of its eleven functions are exact, and
`worldplanet_update` is the remaining 3,136-byte function.

| Measurement | Before | After |
| --- | ---: | ---: |
| Whole-TU objdiff fuzzy match | 99.47965% | 99.81221% |
| `worldplanet_update` fuzzy match | 99.15179% | 99.69388% |
| Update instruction count (retail: 784) | 783 | 784 |
| Exact functions | 10 / 11 | 10 / 11 |
| Exact assigned data bytes | 344 / 344 | 344 / 344 |

The three five-entry orbit-ID, angle-offset, and flight-path-ID arrays
were incorrectly modeled as one `WorldPlanetObjectTables` struct.
Independent array definitions reproduce retail's common `.data` base,
indexed orbit-ID loads, and later angle-address computation. MWCC still
shares a base register between the arrays. A common register base alone
therefore does not establish a source-level struct, and the previous
claim that this instruction shape was unreachable was too strong.

The arrays retain their original order, addresses, sizes, and contents:
`0x8032A178`, `0x8032A18C`, and `0x8032A1A0`, each 20 bytes. They are now
private to the TU. The following unlock-gamebit array is accessed by its
own name instead of walking beyond the old struct. This change improves
the update to 99.66199% and allows direct flight-path array indexing in
both loops without the former pointer casts.

An inlined Fox-spawn helper preserves the retail instruction sequence
and places the setup-source pointer in the correct register. It raises
the update to 99.69388%, without emitting another function or changing
the constant pool. The TU keeps the common GC/1.3 game compiler and its
existing `nopeephole,noschedule` and automatic-inlining settings.

The remaining differences are the selected-object pointer's stack spill
and register assignments in the final orbit loops. Separating that
pointer from the address-taken camera-action ID removes the spill but
changes register allocation throughout the function, reducing the unit
to 99.31925%. Shared loop counters and further helper extraction also
failed to improve on the retained source. These are measured failures
of those source shapes, not evidence that the remaining match is
impossible. The neighboring `../dinosaur-planet` source tree yielded no
WORLDplanet/world-map implementation to use as a donor.

A diagnostic full link that substitutes only this source object leaves
42 differing bytes in `.text`. Every allocated data section, section
address, and section size agrees with the retail-backed matching link.
The TU must remain `NonMatching` until those code bytes are resolved;
the strict checksum currently uses its retail object.

The generated DLL path and TU split boundaries are unchanged. Validation
includes the slot-466 scaffold audit, `ninja all_source`, and strict
matching `ninja`, with 30-second timeouts on both builds. Formatting is
kept in a separate commit and checked for object identity, together with
`clang-format --dry-run --Werror` on the source and canonical header.
