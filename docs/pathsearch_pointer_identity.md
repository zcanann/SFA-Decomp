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
