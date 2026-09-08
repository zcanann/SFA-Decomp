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

## Indexed formatter recovery

`debugPrintfxy` now uses one signed character index and an unsigned-byte text
buffer. The pre-increment loop starts its index at -1; it never constructs a
pointer before the buffer. This replaces two artificial one-element pointer
arrays and their manually synchronized cursors.

With the TU's `nostrength` restriction removed, GC/1.3 generates both retail
cursor inductions from the indexed loop and matches all **106 instructions /
424 bytes**. Keeping `nostrength` produces indexed loads instead; a conventional
post-increment `for` loop produces one cursor, also unlike retail. No assembly,
per-function profile, compiler-version override, or section directive is added.
The rest of the existing TU profile remains provisional.

This is an explicit temporary regression in fuzzy similarity, not an aggregate
similarity win. All ten previously exact functions remain byte-identical, and
the new exact formatter increases the TU to 11/14 exact functions. The other
two affected functions still contain manually advanced framebuffer offsets:

| Function | Before | After | Retail / new instructions |
| --- | ---: | ---: | ---: |
| `debugPrintfxy` | 99.386795% | 100% | 106 / 106 |
| `debugTextDrawToFrameBuffer` | 97.65625% | 81.385414% | 96 / 90 |
| `errorThreadFunc` | 99.95389% | 85.09943% | 694 / 767 |

Whole-TU fuzzy similarity changes from 99.78832% to 93.79543%. All allocated
non-text section bytes, sizes and alignments, and non-text named symbol layouts
are unchanged; all 10,272 assigned data bytes remain exact. The remaining
framebuffer loops need source recovery under this common profile, not a
function-specific rollback of strength reduction. Straight indexed scanline
helpers and dead-store/propagation flag probes did not recover their matches
and are not retained.

`python -m unittest discover -s tools -p test_debug_printfxy.py` tests the
production formatter and font view at host `-O0` and `-O2`. It covers disabled
and empty input, every nonzero byte, lowercase folding, tabs including negative
starting coordinates, newlines, spaces, embedded termination, a 255-byte input,
64 randomized strings, both framebuffer dispatches, and restoration of the
original framebuffer. Changing space advance from eight to nine in memory
fails both layout tests. Formatting is mocked as a `%s` copy and rasterization
as recorded glyph calls; these tests do not validate MSL variadic formatting,
overflowing input, or hardware framebuffer writes.

A full `ninja all_source` rebuild and a fresh strict DOL checksum check pass.
The unit remains `NonMatching`: the checksum uses its retail object, while
the exact formatter result is independently checked against the source object.

## Shared log-rectangle recovery

The reposition, newline, and screen-wrap paths in `debugPrintDrawRecord` now
reuse `debugDrawLogRect`, the existing helper used by `debugPrintDraw`. That
helper in turn reuses `debugPrintFillRect` for the current RGBA color. Three
copies of the bounds calculation and their unused locals are removed, without
adding another abstraction or changing the TU compiler profile.

The helper retains the unsigned coordinate arithmetic, zero-extent rejection,
two-pixel horizontal padding, ten-pixel height extension, per-axis scale/bias,
and truncation at each scaled coordinate. The wrap boundary remains strictly
greater than the screen width minus sixteen, and record boundaries still draw
only on pass zero.

`debugPrintDrawRecord` improves from **99.791664% to 99.90131%**, with 456 retail
instructions, no structural differences, and **17 to 9** differing words.
The residual is a register exchange in the wrap path. All thirteen other
function bodies remain byte-identical, including the exact `debugPrintDraw`
and `debugPrintfxy`. Non-text sections, named symbol layouts and data
relocations are unchanged. The only changed resolved text relocations are
the two X/Y start-coordinate load pairs, now in retail order. Anonymous
literal names change, but their physical destinations do not.

`tools/test_debug_record_rectangles.py` compiles the production record decoder
and both rectangle helpers at host `-O0` and `-O2`. It checks padding around
zero, one, and two; empty extents; fractional scales; newline/reposition/wrap
dispatch; both passes; exact wrap thresholds; current RGBA color including
zero-valued payload bytes; scale-bias commands; consumed record length; and
cursor updates. Glyph widths and drawing calls are mocks, not a font/GX
emulation. Inputs stay within the defined float-to-unsigned conversion range.
Changing the left padding from two pixels to one in memory fails all three
rectangle tests. Both debug test suites and both build gates pass.
