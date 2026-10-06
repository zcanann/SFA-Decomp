# Path-search pointer identity

The full 913-unit PAL rev1 manifest initially differed from retail by two bytes
in one instruction, with every section address and size already correct.
`pathSearchExpandNode+0x14C` stored through `r13-0x7E38` instead of
`r13-0x6480`. Its old EN-address symbol resolved to PAL initialized data at
`803DCD08`, rather than the pointer at `803DE6C0`.

The complete `pathSearchExpandNode` function has a unique normalized match in
every verified original DOL. Its `stw r28,disp(r13)` at offset `0x14C`, together
with each retail r13 base, independently identifies the destination:

| Version | Instruction | Pointer destination |
| --- | --- | --- |
| EN | `8004B0EC` | `803DCD08` |
| EN rev1 | `8004B268` | `803DD988` |
| JP | `8004B10C` | `803DCE28` |
| PAL v1.0 | `8004B2D0` | `803DE500` |
| PAL rev1 | `8004B2D0` | `803DE6C0` |

The regional small-data audit independently reports the PAL rev1 mapping error.
All five destinations are four-byte symbols within `main/pi_dolphin.c`'s
existing small-BSS span. Zero-filled bytes alone do not establish this identity.

The source stores the last encountered linked point whose type is not
`ROMCURVE_TYPE_TRICKY`; the shared name is now
`gPathSearchLastNonTrickyPoint`. Its definition, header declaration and sole
consumer are renamed together. Storage type, declaration order, ownership and
all neighboring definitions remain unchanged. The unrelated PAL rev1
`lbl_803DCD08` in `.sdata` remains intact.

All five versions pass `all_source`, and individual path-search source links
reproduce their original DOLs. Direct objdiff comparisons keep path search exact.
Both edited source objects preserve allocated bytes, section layout, relocations and symbol
properties except for the renamed identity; every other source object remains
byte-identical. EN passes its strict checksum.

The complete manifests now also reproduce both PAL originals: 918 source units
for v1.0 and 913 for rev1. The remaining units and automatic gaps still use
retail objects. Progress counts are unchanged; this repairs final linkage for
source units already credited as matching. The partially matched
`pi_dolphin.c` owner is not promoted or substituted in these tests.

## Native heap and target identity (2026-10-06)

`pathSearchHeapInsert` now uses `PathHeapEntry` fields throughout. It no longer
alternates word/halfword views or truncates heap addresses to `int`. The
condition retains an explicit `s32` parent index, as the existing sift-up
helper already does. On MWCC, `s32` is `signed long`, distinct from the local
`int` index: this keeps the condition's indexed load separate from the body's
entry address and preserves every retail instruction. Without that conversion,
MWCC shares the address and removes one instruction per insertion. This
supersedes the earlier conclusion that raw heap accesses were necessary.

`PathSearch.target` and `pathSearchBegin` now use `ptrdiff_t`. The field remains
four bytes at target offset `0x10`; on a native 64-bit host it can also hold the
curve pointer compared by the matcher's default branch. Tricky points instead
interpret it as a walk-group ID. All four recovered calls currently use that
ID mode. Foxhollow independently widens this mixed-purpose target and the heap
addresses; Dinosaur Planet's `src/route.c` supports the typed heap structure,
inverted insertion priority, and sift helper boundaries.

The stepping loop retains a pointer-preserving `void*` conversion for its local
search alias. Removing the conversion swaps the search and step-count register
homes; the old pointer-to-`int` round trip was unnecessary. The Tricky candidate
route helper forwards the same pointer-width target type. Leaving its argument
as `int` introduces a loop-invariant conversion and regresses that caller's
register allocation. Updating its declaration and definition restores the
complete Tricky object to its original bytes; no other Tricky code is changed.

The heap still reserves index zero as a maximum-priority sentinel and inverts
new distances with `UINT32_MAX - distance`. Existing-route updates retain
retail's direct, uninverted priority. High-bit parent indices remain rejected,
including valid-looking indices other than `0xFF`. The 254-node, 254-entry heap,
and 100-point path allocation contract is unchanged.

`tools/test_pathsearch_native.py` executes the production TU and canonical
records at `-O0` and `-O2` with ASan/UBSan and pointers above 4 GiB. Its 700 cases
include an independent unordered-set priority oracle, both sift directions,
equal/extreme priorities, all parent-index byte values, full-width pointer
targets, forward/backward routes, game-bit and subtype gates, cycles, existing
route updates, allocation boundaries, and capped path reconstruction. Five
temporary negative controls catch truncated heap/search pointers, a narrowed
target field, changed insertion encoding, and a weakened parent-index check.

All five versions pass `all_source`, the strict checksum, and the complete
objdiff inventory check. Path search is 11/11 functions and all code/data exact;
the caller's entire Tricky TU remains exact. All other source objects are
byte-identical to baseline, including every header consumer. Path search differs
only in one anonymous literal symbol number at its unchanged location; allocated
bytes, named symbol layouts, and normalized relocations are identical. Each
source-linked DOL is byte-identical to its hash-verified original. The existing
TRK vector-boundary and MusyX discarded-exception-data report artifacts are
unchanged. The active TU and owning header pass `clang-format --dry-run --Werror`
without further formatting changes; their post-format object hashes also agree.
