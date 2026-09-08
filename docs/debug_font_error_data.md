# Debug font and fatal-error text

The EN block at `8031D060..8031D2A4` is 580 bytes of packed font and diagnostic
data, previously named `gDebugFontGlyphs`. Its definition remains one byte block,
now named `gDebugFontAndErrorData`; the active symbol config retains its address
and extent. `DebugFontErrorDataView` is a typed view of these existing bytes,
not a claim that the original source declared one font/error structure.

`debugPrintfxy` accepts bitmap characters `0x21..0x5A`, with five bytes per
glyph, and folds lowercase ASCII into uppercase first. The view therefore
exposes 58 five-row glyphs. Bytes `+0x122..+0x140` are not consumed by this
renderer and remain an opaque 30-byte tail; the gap does not justify adding
six more usable glyphs.

`errorThreadFunc` consumes fourteen null-terminated texts from the same block:

| Offset | View field | Text or format |
| --- | --- | --- |
| `140` | `threadFormat` | `\terrorThreadFunc %x` |
| `154` | `exceptionLabel` | `Exception:` |
| `160` | `systemReset` | `System reset` |
| `170` | `machineCheck` | `Machine check` |
| `180` | `alignment` | `Alignment` |
| `18C` | `performanceMonitor` | `Performance monitor` |
| `1A0` | `systemManagementInterrupt` | `System management interrupt` |
| `1BC` | `memoryProtection` | `Memory Protection Error` |
| `1D4` | `unknownError` | `Unknown error` |
| `1E4` | `stackTraceLabel` | `Stack trace` |
| `1F0` | `stackDepthFormat` | `Stack %x; depth %d` |
| `204` | `stackWordsFormat` | `\t%08x\t%08x` |
| `210` | `registersLabel` | `General Purpose Registers` |
| `22C` | `registerWordsFormat` | `\t%08x\t%08x\t%08x\t%08x` |

Each text field includes the trailing bytes before the next text. Size and
offset assertions verify the complete view and all fourteen text starts.
The packed definition retains every padding byte and its `.data` placement;
the messages have not been split into independently emitted arrays. The
separate DSI/ISI and PC/SP format arrays retain their existing ownership.

All fourteen function bodies, all allocated section bytes and layouts, and all
resolved relocation destinations are unchanged. The renamed data symbol keeps
its offset, size, linkage, and visibility; no other named symbol changes.
The complete 580-byte object span also matches the retail EN DOL directly.
Objdiff retains 10/14 exact functions and all 10,272 matching data bytes.
This is data recovery with unchanged match credit.

Both `ninja all_source` and the strict retail DOL checksum pass. The TU remains
`NonMatching`; its preserved source output is verified by object comparison,
while the matching DOL checks integration using the retail object.
