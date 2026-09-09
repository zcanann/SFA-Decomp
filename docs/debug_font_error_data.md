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

## Framebuffer raster and horizontal separators

The glyph rasterizer now names the framebuffer stride, five glyph rows, eight
bits, and its four pixel offsets as a two-by-two footprint. Consecutive set
bits start one pixel apart, so the footprint can reach a ninth pixel. Each
glyph row occupies two scanlines. The two 16-byte `DCStoreRange` requests per
glyph row are retained, including for empty rows. This cleanup preserves the
entire function's generated bytes and does not earn additional match credit.

The three horizontal error-display separators now share an indexed inline
helper. The first two draw 640 pixels on rows 58/57 and 240 pixels on rows
91/90. The third uses the stack-display cursor plus 76 and conditionally draws
the preceding row. The caller retains each debug-enable guard. This replaces
manually advanced offsets with the row, width and column relationship; the
helper's name and source boundary are reconstructed, not recovered symbols.

Under the existing GC/1.3 profile, the variable-row path reproduces retail's
five-pixel unroll and its alternate single-row loop. The constant-row calls
still have different address calculations and unrolling. `errorThreadFunc`
improves from **85.09943% to 86.35591%**, with **767 to 748 instructions** against
retail's 694. Whole-TU fuzzy similarity improves from **93.82081% to 94.26345%**.
The other thirteen function bodies, all allocated non-text sections and their
named layouts and resolved relocations are unchanged. Eleven functions remain
exact, and all 10,272 assigned data bytes still match. Anonymous symbol numbers
change; the raw object is not identical.

`python -m unittest discover -s tools -p 'test_debug_*.py'` passes the formatter
tests and a production-source raster harness at host `-O0` and `-O2`. The new
harness checks complete guarded framebuffer contents for empty/full/single-bit
glyphs, edge positions, disabled drawing, separator widths, row zero and the
bottom row, plus the requested cache ranges. Mutating the preceding separator
row or a glyph pixel's increment fails the pixel checks. This does not emulate
PowerPC cache-line rounding, GPU scanout or the exception thread itself.

Both `ninja all_source` and the strict retail DOL checksum pass. The TU remains
`NonMatching`, so the checksum validates integration through its retail object;
the source improvement is measured separately by objdiff.

## Debug-log command protocol

The decoder and glyph-color writer now share a private `DebugLogCommand` enum.
Decoder locals distinguish the record start, byte cursor, current byte,
horizontal advance and tab remainder. The recovered byte format is:

| Byte | Command | Payload |
| --- | --- | --- |
| `81` | Glyph color | Four RGBA bytes; applied on the glyph pass |
| `82` | Position | Little-endian 16-bit X and Y |
| `83` | Proportional width | None |
| `84` | Fixed width | None; printable bytes advance seven pixels |
| `85` | Rectangle color | Four RGBA bytes; applied on pass zero |
| `86` | Tab width | Little-endian 16-bit width |
| `87` | Scale bias | Unsigned X and Y bytes |

Payload zero bytes do not terminate a record. Proportional spaces advance six
pixels, while other glyph advances come from the atlas metrics. Tabs advance
to the next multiple of the configured width, including a full tab when already
aligned. Position, newline and screen wrap close the current rectangle on pass
zero. The enum names describe the observed decoder and writer; they do not
claim recovered original identifiers.

The existing host harness now also checks both width modes, a 256-pixel tab
payload containing zero, aligned and unaligned tabs, and glyph-color payloads
containing zero on both passes. Ten debug tests pass at host `-O0` and `-O2`.
The production object is byte-identical before and after this recovery,
including after formatting, so no additional matching credit is claimed.
Both full build gates pass.

## Separator countdown refinement

On top of `620b501643`, the shared separator loop retains an indexed column
but counts down its remaining width. This recovers more of retail's unrolling
without changing compiler flags. The one-element `self` array is removed;
the diagnostic now prints `errorThreadFunc` directly. All call-site enable
guards and the preceding-row condition remain intact. Width is nonnegative
at every real call site, as required by the countdown loop.

`errorThreadFunc` improves from **86.35591% to 90.148415%**, shrinking from 748
to 717 instructions against retail's 694. Structural differences drop from
115 to 101, while operand differences increase from 47 to 83. Whole-TU fuzzy
similarity rises from **94.26345% to 95.599495%**. Eleven of fourteen functions
remain exact; this is a partial-match gain, not a new exact function.

The other thirteen function bodies and their relative relocations are unchanged,
as are all non-text sections and their named layouts and resolved relocations.
The crash thread's external call order is unchanged. Its shorter body moves
the following handler's text address by 124 bytes. The source object SHA-256 is
`ce7d69124398f30ea1136f606b6242c8beeb4ef49d0472fcc463a000d75b199d`.

The framebuffer harness now builds and unloads its DLLs on Windows as well as
supporting the existing POSIX path. It adds 80 randomized separator cases and
extracts the actual guarded call sites to check both stack-layout endpoints
and zero/nonzero enable values. Omitting the preceding row or shortening the
240-pixel call fails the checks. All eleven debug tests pass at host `-O0` and
`-O2`, alongside `ninja all_source` and the strict retail checksum gate.

## Shared unsigned glyph-pixel boundary

The glyph rasterizer now calls a private inline pixel writer with a `u32`
linear pixel index. The four caller-side footprint indices remain signed.
This models a type boundary at the repeated write operation, rather than
changing the coordinate API or forcing the compiler's loop settings.
The helper name and original helper boundary are inferred, not leaked symbols.

With the existing GC/1.3 profile, the unsigned parameter preserves both the
pixel-index and byte-offset inductions seen in retail's two-bit unroll. A
signed helper produces the previous object bytes; making the footprint array
unsigned produces only 90 instructions and does not recover the pattern.
An explicit unsigned cast at each write produces the same result as the
retained helper. The helper centralizes that contract at one native array access.

All five verified retail versions share the same 384-byte function body.
In each version, `debugTextDrawToFrameBuffer` rises from **81.385414% to
97.65625%**, with **90 to 96 instructions**, matching retail's length.
Mnemonic-alignment differences fall from thirteen to two and operand
differences from sixty to four. The remaining differences exchange the X
coordinate and lower-row-offset registers and move the glyph-pointer copy.
The save/restore calls now cover r25 through r31, as in retail, rather than
r26 through r31.

Whole-TU matching improves from **95.599495% to 96.39239%** in every version.
All thirteen sibling function bodies, all allocated non-text section bytes,
their named layouts, and all 10,272 assigned data bytes remain unchanged.
Function-relative relocation destinations are unchanged except for the
corrected register-save/restore pair. Later function addresses advance by
24 bytes; no new exact function is claimed (eleven of fourteen remain exact).

The framebuffer harness extracts and compiles the production pixel helper.
Its glyph cases now also include negative columns with valid linear offsets
and footprints crossing a scanline boundary, preserving the lack of clipping.
The complete guarded framebuffer and all ten cache-store requests are checked
at host `-O0` and `-O2`; all eleven debug tests pass. These are host execution
checks, not PowerPC cache or display-hardware emulation.

## Shared crash-screen separator pixels

The three horizontal separators now advance signed pixel indices for the current
and preceding scanlines, then pass them through the same unsigned pixel writer
as glyphs. The helper and fixed color are named `debugDrawTextPixel` and
`DEBUG_TEXT_COLOR` to reflect both consumers. Their names and source boundary
are reconstructed; no compiler settings change.

Both parts matter under GC/1.3: routing the old column-indexed loop through the
writer grows the crash thread to 728 instructions, while advancing the two
pixel indices reproduces retail's loop structure. The current-row write still
precedes the previous-row write, the preceding row is conditional on `row > 0`,
and the width countdown and all caller-side enable guards are preserved.

`errorThreadFunc` improves from **90.148415% to 99.71614%**, shrinking from
**717 to 694 instructions**, exactly retail's length. Structural differences
fall from 101 to zero, and operand differences from 83 to 35. The residual is
the font-block/self-address register exchange and the order of two vertical-rule
initializations. Whole-TU fuzzy matching rises **96.39239% to 99.76295%**;
eleven of fourteen functions remain exact.

EN v1.0, EN revision 1, JP, and PAL revision 1 have SHA-1-verified inputs and
identical address-normalized retail crash-thread bodies. All four builds produce
the same resulting source object. The thirteen sibling function bodies, every
function's ordered relocation destinations, and all allocated non-text bytes
and named layouts are unchanged. The following handler moves back 92 bytes;
all 10,272 assigned data bytes remain exact. The TU remains `NonMatching`.

All eleven debug tests pass at host `-O0` and `-O2`. The existing guarded-pixel
checks cover all three real separator calls, zero width, row zero, the bottom
row, and eighty randomized row/width pairs. Mutating the preceding-row stride
from one pixel to two fails the framebuffer comparison. Formatting preserves
the raw object; `ninja all_source` and the strict retail checksum gate pass
with 30-second bounds.

## Native crash-screen backdrop loop

The backdrop fill is a column-major loop over the 640-by-480 framebuffer. A
normal pair of `for` loops, using `(debugDrawFrameBuffer + y * width)[x]`,
reproduces both existing inline expansions in `errorThreadFunc`. GC/1.3
strength reduction and unrolling produce the eight row stores and 60 inner
iterations previously written out by hand. The source now names the framebuffer
height and backdrop color and removes the integer pointer casts and explicit
byte strides.

The row-pointer expression matters: flattening it to
`debugDrawFrameBuffer[y * width + x]` changes the compiler's induction variables
and instruction stream. The retained expression preserves every function byte,
allocated section, named symbol layout, and physical relocation destination in
EN v1.0, EN revision 1, JP, and PAL revision 1. Compiler-generated anonymous
labels are renumbered; complete object hashes therefore change. All four objdiff
reports remain unchanged, including the crash thread's 694 instructions and
35 operand differences. This is source recovery, with no claimed matching gain.

The guarded framebuffer harness now also executes the production backdrop loop
at host `-O0` and `-O2`. It verifies all 307,200 pixels have color `0x1080`,
both external guards remain intact, disabled drawing preserves the framebuffer,
and the helper does not flush the cache. All twelve debug tests pass.
All four `all_source` builds and the strict EN retail checksum gate pass with
30-second bounds.
