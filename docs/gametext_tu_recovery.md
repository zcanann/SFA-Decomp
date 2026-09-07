# Gametext TU recovery

The six former gametext/render fragments are reunited in `src/main/gametext.c`.
This is a source-boundary correction, not a claim that the resulting source is
fully matching. The original file name remains unproven.

## Retail evidence

The EN text span is `80015BC8..8001B46C`: 54 functions, 22,692 bytes. Physical
retail r2-relative loads connect functions previously assigned to different
fragments to the same compiler-generated constants:

| Address | Value | Representative consumers |
| --- | --- | --- |
| `803DE6F0` | unsigned integer conversion bias | `gameTextRenderStrs`, `gameTextWrapLines`, `textRenderStr`, `gameTextMeasureString` |
| `803DE6F8` | signed integer conversion bias | the above and `gameTextTickReveal` |
| `803DE704` | `0.0f` | renderer, `gameTextGet`, `gameTextRun`, renderer initialization |
| `803DE708` | `1.0f / 256.0f` | wrapping, rendering, measurement |
| `803DE71C` | `120.0f` | `gameTextGet`, `gameTextRun` |

No function outside the recovered span consumes this pool. The adjacent subtitle
TU uses separate signed/unsigned biases and zero at `803DE728`, `803DE738`, and
`803DE730`. Integer-only `gameTextMeasureById` sits inside the connected span.
These are physical address checks, not comparisons of ambiguous `@N` names.

The old fragment-specific optimization profiles are not evidence of separate
original compiler invocations. One common GC/1.3 profile now applies. Disabling
automatic inlining preserves the retail calls to string-copy and text helpers;
automatic inlining changes that call topology. Other optimization details remain
provisional. A no-propagation experiment restored `gameTextGet` before literal
recovery but reduced the combined exact-function count; it was not retained as
a special-case profile.

## Storage recovered

The source emits the full 48-byte pool at `803DE6F0..803DE720`, in retail order:
two conversion-bias doubles, then `2`, `0`, `1/256`, `0.5`, `4`, `8`, `32`, and
`120` as floats. Former external scalar references are now literals. Correcting
two `gameTextRun` timer comparison locals from `double` to `f32` avoids duplicate
double zero/120 constants; no named dummy constants or placement attributes are
needed.

Moving language names beside their table, after the map-directory table, restores
the physical small-data order. BSS definitions remain in their original relative
order after all functions. Defining them before their consumers instead changes
MWCC's allocation to first-reference order. Current named storage addresses all
agree with retail. The initial merger retained these coarse symbol extents;
the native BSS recovery below replaces the oversized fallback/scratch records:

| Object | BSS offset | Bytes |
| --- | --- | --- |
| `gGameTextBase` | `0` | 32 |
| `sGameTextFallbackBufSlots` | `32` | 32 |
| `sGameTextFallbackDefs` | `64` | 640 |
| `sSubtitleCtrlCmdScratch` | `704` | 2304 |
| command slots | `3008` | 2560 |
| `gGameTextCharsets` | `5568` | 160 |
| `curGameTexts` | `5728` | 608 |

All non-relocation `.data` bytes match. Of its 172 relocations, 144 storage
pointers preserve exact destinations; the other 28 are jump-table entries
(12 renderer, 16 command-runner) whose case ordering and branch destinations
were reviewed against both objects. The compiler emits 12,361 bytes versus the
retail carve's 12,368: the extra seven retail bytes are trailing zeros before the
next aligned TU, not a recovered source object.

## Color contract

The merger exposed inconsistent byte/int declarations of `gameTextSetColor`.
The canonical API now accepts integer channels, matching the existing majority
of callers, and explicitly narrows queued command values to bytes. Direct mode
already writes byte storage. The per-consumer signature-selection macro is gone.
This is a consistent reconstruction, not proof of the original argument types:
the byte-argument alternative keeps the setter exact but regresses six callers,
including five previously exact linked units. Integer arguments leave those
callers unchanged, but introduce four redundant narrowings in the setter and
change several game-UI functions under the current compiler profile.

`python tools/test_gametext_color.py` executes the production setter in both
modes using the public declaration: 1,028 cases cover all byte values, signed
integer boundaries, random channels, untouched neighboring commands, and direct
versus deferred state changes.

## Checkpoint result

The merged TU is 97.59281% fuzzy, 43/54 functions exact, with 22,560 source text
bytes versus 22,692 retail. Its `.sdata2`, `.sdata`, `.sbss`, and `.bss` sections
are exact in objdiff; named storage offsets were checked independently. Only
gametext and its game-UI consumer change generated objects relative to the
pre-merge baseline. All other previously built source objects remain identical.

Global exact-code credit drops from 2,636,000 to 2,630,140 bytes. Exact-data credit
drops from 1,206,041 to 1,193,705 bytes because the merged `.data` section includes
nonmatching jump tables, while the newly recovered pool adds 32 bytes. This
regression is retained to recover the evidenced TU and expose the actual remaining
work. Both `ninja all_source` and the strict retail checksum target pass; the
merged TU remains `NonMatching`, so that checksum does not validate its C code.

EN rev1, JP, and both PAL split projections were refreshed for this span only.
Obsolete fragment matching entries were removed; unrelated projection changes
were excluded.

## Native disc-font resources

The next pass replaces the `char[1360]` font buffer with 85 mutable `TextGlyph`
records. The old Japanese resource aggregate incorrectly grouped the English
glyph table with Japanese message text. Both artificial resource aggregates are
now separate loading strings, seven-entry `GameTextDef` arrays, and the English
43-entry glyph array:

| Native object | Retail address | Bytes |
| --- | --- | --- |
| `sJpDiscStatusGlyphs` | `802C8F40` | `550` |
| `sJpDiscLoadingMessage` | `802C981C` | `10` |
| `sJpDiscStatusMessageTable` | `802C982C` | `54` |
| `sDiscStatusGlyphs` | `802C9880` | `2B0` |
| `sDiscLoadingMessage` | `802C9D58` | `B` |
| `sDiscStatusMessageTable` | `802C9D64` | `54` |

Addresses and sizes in this table are hexadecimal. Retail atlas setup explicitly
selects 85/43 glyphs and seven messages, and advances each glyph by 16 bytes.
Independently, the glyph keys in each language exactly follow first occurrence
order across its seven messages: 85 distinct Japanese-message characters and 43
English-message characters, with no extras. This also disproves the previous
comment describing the English glyph table as part of the Japanese font.

Standalone arrays are a plausible declaration model, not proven original source
syntax. All resource bytes and normalized storage-pointer destinations remain
unchanged. The English loading string is naturally 11 bytes; compiler alignment
supplies the next byte before its message table, without a padded string type.
The atlas builder now selects these native arrays directly. The three lookup
functions use a typed parser-message pointer instead of reaching up to `0xF10`
bytes beyond the former 1,360-byte glyph array.

Atlas locals distinguish compressed ROM data, decoded font data, glyph pixels,
and tile/pixel coordinates. Known SDK encoding/ROM-size definitions and the
system-font ID replace raw values. Those naming and API changes preserve the raw
object hash. The overlapping-word SJIS lookup and the oversized final flush are
unchanged; this pass does not silently repair either behavior.

`python tools/test_gametext_font_resources.py` checks the built source object's
symbol extents, relocated resource bytes, loading-string termination, and exact
first-occurrence glyph order against the retail DOL. Three tests pass; corrupting
one glyph key makes both byte comparison and character coverage fail. These are
resource tests, not execution tests of the atlas drawing loop.

The resulting TU is 97.423584% fuzzy, 41/54 functions exact, versus 97.59281% and
43/54 before this pass. Only the three getters and atlas builder change function
bytes; all other source objects remain identical. The two lost exact functions
account for 940 bytes of code credit. Data credit and the exact 48-byte constant
pool are unchanged. Both source compilation and the strict checksum gate pass;
gametext remains `NonMatching`.

## Measurement helper

Calling the existing `gameTextIdExists` inline helper from `gameTextMeasureById`
replaces the fragment's duplicated search and synthetic `(found = 0, 0)` loop
condition. This reproduces the complete 312-byte retail function with the common
TU profile: 99.48718% becomes 100%. No other function bytes or data sections
change. Normalized relocation destinations also remain identical.

Cursor arguments now carry their meaning through the measurement, renderer, and
display wrappers. The renderer's former `maxX/maxY/minX/minY` local names were
misleading: its measurement outputs are actually min X, max X, min Y, max Y in
that order. Naming them correctly makes the vertical-alignment calculation read
as window height minus measured height, without changing allocation or codegen.

`python tools/test_gametext_measure.py` executes the production helper and bounds
function with a mocked renderer. Its 54 cases cover first/middle/last IDs, all
successful-path output-pointer combinations, empty tables, unavailable fonts,
absent IDs, mode transitions, and signed quarter-pixel conversion. The retail
missing-ID path still requires all four output pointers. A wrong shift count
fails 24 cases. Gametext now has 42/54 exact functions, with unchanged data credit.

## Native runtime storage

The 32-byte `gGameTextBase` is no longer used as a fictitious 6,336-byte object.
`GameTextRuntime` and its raw-offset macros are removed. Getters, initialization,
the command runner, and the two loaders address the actual arrays directly.
`gGameTextLastEntry` is a `GameTextDef*`; the misleading fallback-buffer pointer
is now a pointer to the selected request-frame delta. Retail assigns `timeDelta`
on a cached lookup and uses positivity to enable elapsed accumulation; this is
not a countdown. A shared inline
helper selects the next fallback slot in all six former copies of that sequence,
with identical generated function bytes to the expanded native-array spelling.

The EN initializer at `8001A280..8001A2DC` runs eight iterations with 12-byte
definition, four-byte pointer, and 64-byte string strides. Its stores establish
both pointer indirections. The reveal updater independently tests the complete
96-byte definition range. The resulting BSS partition is:

| EN address | Object | Bytes |
| --- | --- | --- |
| `80339980` | `sGameTextFallbackElapsedFrames[8]` | 32 |
| `803399A0` | `sGameTextFallbackRequestDelta[8]` | 32 |
| `803399C0` | `sGameTextFallbackDefs[8]` | 96 |
| `80339A20` | `sGameTextFallbackStrings[8]` | 32 |
| `80339A40` | `sGameTextFallbackBuffers[8][64]` | 512 |
| `80339C40` | `sSubtitleCtrlCmdScratch[16]` | 192 |
| `80339D00` | `sGameTextPath` | 64 |
| `80339D40` | `sGameTextCommandStringBuffer` | 2048 |
| `8033A540` | command slots | 2560 |
| `8033AF40` | `gGameTextCharsets[4]` | 160 |
| `8033AFE0` | `curGameTexts[8]` | 608 |

The path and command-string starts come from their consumers; their extents
follow the next independently used buffer, not a recovered bounds check. Both
remain unbounded as in retail. Standalone declarations versus original aggregate
membership remains a source hypothesis, but no recovered consumer needs the
giant runtime overlay or accesses these buffers as one aggregate.

Two parser bugs are preserved explicitly. At `80018C1C..80018C28`, the command
count increments before the greater-than-16 check. Encountering a seventeenth
command therefore allocates and copies 204 bytes, overreading the first 12 path
bytes after the 192-byte scratch array. The record pointer also never advances:
accepted commands repeatedly overwrite record zero, leaving the other records
and omitted argument fields stale. Neither an extra scratch element nor a cursor
increment has been invented to conceal or fix this. The allocation/copy size now
uses `sizeof(SubtitleCmd)` and retains the exact retail parser instructions.

`python tools/test_gametext_runtime.py` checks all eleven BSS symbol offsets and
extents in the MWCC object, then executes production initialization, fallback
selection, getters, and parser bodies in a host harness. Its 160 host cases cover
148 initialized windows, four font records and their texture pointers, all eight
fallback entries and pointer chains, unavailable-font ring wrap, successful
lookups, new/cached missing IDs, request-delta thresholds, and parser count/overwrite
behavior. Decoder, formatting, allocation, font-atlas construction and memory
store creation are mocked. The memcpy mock records the overread size without
performing an out-of-bounds host read; retail adjacency is checked separately.
Reducing the ring wrap threshold by one produces 12 failures and no harness
errors. The loader/command-runner behavior is reviewed in the source/object diff,
not executed by this harness.

All eleven BSS objects have the offsets above; existing small-data/storage
offsets and all non-text section bytes are unchanged. Only five functions change:
`gameTextGet` (652 to 676 bytes), `gameTextRun` (1452 to 1524), renderer
initialization (492 to 532), sequence loading (588 to 608), and map loading
(680 to 700). All other source objects remain byte-identical. Gametext changes
from 97.43063% to 96.3321% fuzzy, retaining 41/54 exact functions. The lost exact
initializer accounts for 492 code-credit bytes; data credit is unchanged.

Defining all native BSS arrays before their consumers makes GC/1.3 emit a real
shared-base symbol and brings the initializer near exact, but allocates arrays
in first-reference order at the wrong physical offsets. Reversing declarations
does not fix that; explicit zero initialization moves them to initialized data.
Neither experiment is retained. Definitions remain at the TU end, where the
compiler emits the exact recovered storage order. Recovering the original
declaration/compilation model is still open; restoring an invented base buffer
or applying placement directives is not a solution.

Both `ninja all_source` and the strict retail checksum gate pass. The TU remains
`NonMatching`, so the strict link does not validate the changed source codegen.

## Shared load-slot search

The three manually expanded eight-slot searches in `gameTextRun`,
`loadGameTextSequence`, and `gameTextLoadForCurMap` now call one private inline
helper. It walks `curGameTexts` in ascending address order, returns the first
record whose `active` byte is zero, and returns null after eight occupied records.
GC/1.3 expands the ordinary countdown loop into the retail eight-test shape. In
the sequence loader, replacing only the expanded expression with this helper
preserves every function byte. A separate typed `LanguageName*` local replaces
its manually shifted byte offset and keeps the language selection before the
heap/state calls, as in retail.

The EN sequence search at `8001A540..8001A5E0` tests byte `0x4A` and advances by
`0x4C` seven times; its final fallthrough supplies a null pointer. The subsequent
store at `8001A5E4` is unconditional. The sequence loader therefore still requires
a free slot, while the map loader leaves its directory/language request pending
when all slots are occupied. Cancellation does not immediately make an active
slot reusable, even when the cancellation callback runs synchronously. Existing
completed allocations can be freed and reused by the same request. These
differences remain explicit at the callers; the search does not reserve or clear
the selected slot.

| Function | Before fuzzy | After fuzzy | Source bytes before / after |
| --- | --- | --- | --- |
| `gameTextRun` | 85.86702% | 88.14096% | 1524 / 1516 |
| `loadGameTextSequence` | 91.82993% | 92.03401% | 608 / 608 |
| `gameTextLoadForCurMap` | 89.66082% | 91.47369% | 700 / 700 |

The TU rises from 96.3321% to 96.54275%, retaining 41/54 exact functions and the
same exact code/data credit. Only these three functions change instruction
bytes. All non-text section bytes and named storage offsets remain unchanged.
The command runner's sixteen jump-table relocations keep the same destination
function and move their case offsets back eight bytes with the shortened search.
The 51 other functions keep their instruction bytes. Formatting is recorded
separately and preserves the complete generated object.

`python3 tools/test_gametext_load_slots.py` executes the production helper, both
loaders, and both DVD callbacks, with allocation and file-I/O mocks. At each of
`-O0` and `-O2`, 402 scenarios cover all 256 occupancy masks (including non-boolean
active bytes), each free-slot position in both loaders and all six languages,
pending map requests, completed-buffer reuse, both cancellation timings, DVD
success/failure and unknown callback records, and rejected state/language/map
requests. A seven-slot mutation fails the suite. The sequence-loader null access
is reviewed in retail assembly rather than executed on the host; the complete
command runner is not executed by this harness. The existing runtime, font,
measurement, and color suites also pass.

Both `ninja all_source` and the strict retail checksum gate pass. Gametext remains
`NonMatching`; these gates establish buildability, not runtime equivalence of
its reconstructed C.

The subsequent [resource-parser recovery](gametext_resource_parser.md) corrects
the overlapping message-header record, introduces native glyph/texture headers,
and replaces the font-record pointer cast with real texture-array indexing. It
also provides compiled-versus-retail PPC execution checks for this parser.

## Bounded initialization loops

`gameTextInitRendererState` now expresses its reverse traversal with integer
indices. The former comma-expression conditions decremented pointers once more
when the count reached zero, forming pointers before their arrays even though
the body did not dereference them. The recovered C now addresses only valid
elements: all 148 windows, eight fallback records and their two pointer levels,
four charsets, and three textures per charset. The final negative value belongs
only to the integer loop counter.

The existing runtime suite checks every initialized element and preserves
unrelated window state. The initializer remains 532 bytes and moves slightly
from 86.333336% to 86.162605% fuzzy. Together with the parser's local-table-base
improvement, gametext rises from 96.39944% to 96.416885%, retaining 41/54 exact
functions and unchanged exact-code/data credit. Only those two functions change
instruction bytes; all non-text section bytes and named storage offsets remain
unchanged. The TU and its canonical header pass clang-format without a
formatting-only diff.

The runtime and load-slot suites, 432 parser emulation comparisons, the strict
retail checksum, and `ninja all_source` all pass for this checkpoint.
