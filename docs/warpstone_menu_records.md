# Warpstone menu record recovery

The warpstone UI sends its six 60-byte menu records to the shared Link menu
interface. It now uses the existing `TitleMenuTextEntry` layout, replacing a
second record definition that hid most fields in 18-byte and 32-byte arrays.
The source edits apply to all five retail versions.

`WarpstoneUI_getMenuItems` copies exactly 0x3C bytes per enabled entry, writes
the text's top coordinate at +0x06, and rebuilds the up/down navigation links
at +0x1A/+0x1B. `Link_setup` copies the same 0x3C-byte records and consumes those
links, the texture asset ID at +0x10, width at +0x14, and flags at +0x16.
The source now names the rewritten fields `textTop`, `upLink`, and `downLink`.
The old `y` name at +0x06 incorrectly conflated text placement with the
separate +0x0C coordinate in the shared record.

All six template records are byte-identical across the five checksum-verified
DOLs. Their explicit initializers expose a -1 texture asset ID, 280-pixel width,
0x0280 flags, navigation links and state, and zeroed slot/timer storage.
Their unusual initial up/down indices are retained: the filtering helper
replaces them before handing the active list to Link. Unknown bytes remain
unknown in the shared definition. The four-byte warpstone gamebit/map-action
record now has size and field-offset assertions beside its definition.

## Regional texture placement

The only differing defaults are the two texture-position words:

| Versions | Texture X | Texture Y | Text/menu Y |
| --- | ---: | ---: | ---: |
| EN v1.0, JP | 310 | 270 | 320 |
| EN rev1, PAL v1.0, PAL rev1 | 320 | 285 | 320 |

The values were read directly from each verified DOL, preserving declaration
order and storage width. `WarpstoneUI_showUI` still draws at `(X - 29, Y + 13)`.
This corrects the regional placement without changing the function's code.

## Validation

All seven functions (1,188 bytes) and all 876 data bytes are exact in every
version. EN rev1 and both PAL versions each gain 16 matched data bytes and one
completed source unit; the seven functions were already exact. The EN and JP
objects remain byte-identical. Each other regional object differs from its old
source object in exactly two bytes, the low bytes of the X/Y defaults.
Every unrelated source object is unchanged.

All five `all_source` builds and native strict checksum targets pass. Both the
all-retail control and a link substituting only the warpstone source object
reproduce each hash-verified original DOL. No symbols, splits, compiler settings
or expected checksums change.
