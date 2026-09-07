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

## Deferred emission and diagnostic literals (2026-09-07)

The native-array emission blocker above is resolved without restoring an
aggregate. Ordinary function definitions are ordered for reverse deferred
emission, with the existing native storage definitions before the bodies.
GC/1.3, disabled automatic inlining, and the optimization settings remain;
the TU now uses the existing deferred variant of that profile. All eleven BSS
objects and every remaining named non-text symbol retain their physical offsets.

The decisive initialized-data evidence is the interleaving of literals and
compiler-generated jump tables. Keeping the named parser-message aggregate and
path-format arrays with deferred emission moves them ahead of both tables.
Writing the six diagnostic messages and two path formats as ordinary call-site
string literals instead emits every string at its exact retail address:

| EN address | Literal / span |
| --- | --- |
| `802C9E04` | `<uninitialised>` |
| `802C9E14` | `<loading>` |
| `802C9E20` | `<file empty!>` |
| `802C9E30` | `<no file!>` |
| `802C9E3C` | `<%d's not in %s>` |
| `802C9E50` | `<%d, doesn't have phrase %d>` |
| `802C9E70` | `gametext/%s/%s.bin` |
| `802C9EC4` | `gametext/Sequences/%d_%s.bin` |

The compiler supplies each alignment gap and pools repeated uses. The six
messages occupy the same 108-byte span, without a padded struct, named dummy
strings, or explicit placement. The renderer's 48-byte jump table precedes that
span; the command runner's 64-byte jump table remains between the two path
formats. All allocated non-text section bytes, lengths, and alignments match the
preceding source object, including the 12,361-byte `.data` extent. This combined
code/storage evidence supports deferred emission and literal diagnostics as a
plausible reconstruction; it does not establish a historical build command.
The existing retail symbol labels remain address anchors for the literal pool.
Their removed public array declarations have no remaining source consumers.

`loadGameTextSequence` becomes exact (588 bytes), raising the unit from 41/54
to 42/54 exact functions. Fuzzy matching improves from 96.46448% to 97.420944%.
`gameTextGet` improves from 89.454544% to 97.30303%, and initialization from
86.162605% to 98.60162%. All previously exact functions remain exact. Seven
functions change code generation; `gameTextGetPhrase` has a small remaining
regression (98.9375% to 98.5875%) as native shared-array addressing replaces
its independent map-name-table address. The unit remains `NonMatching`.

The runtime fixture now classifies diagnostic formats by string content rather
than the addresses of fields in the removed aggregate. The loader fixture uses
the production bodies' literals. The compiled-resource checks compare the
literal spans directly at retail addresses and retain the named-resource extent
checks. All sixteen gametext tests pass, including 402 load-lifecycle scenarios
at each of host `-O0` and `-O2`. Existing parser, fallback-ring, text measurement,
color, and texture-resource checks remain enabled.

`ninja all_source` and the strict matching checksum both pass with 30-second
limits. The resulting DOL is byte-identical to retail. The matching link still
uses this incomplete unit's retail object, so the checksum does not establish
source-linked correctness. Objdiff confirms that no other unit's match measures
change; the separately checked data bytes and symbol offsets preserve storage.

The TU and canonical API header pass `clang-format --dry-run --Werror`.
Formatting produces no source diff and preserves the complete object; no separate
formatting commit is needed. The shared text-rendering header edit is limited to
removing the two obsolete format-array declarations.

## Shared immediate charset selection (2026-09-07)

`gameTextRun` improves from 90.539894% to 91.27128%. The queued charset
command now shares the private inline `gameTextSelectCharset` helper with
`gameTextSetCharset`. It selects the font record, records the charset, and
performs the existing clear-color rectangle and reveal reset for charset 2.
The helper name and boundary are reconstructed source structure, not recovered
original symbols.

Retail captures the command argument once and keeps it across the global
font/charset stores. The previous source reread `cmd->arg0` twice after those
stores. Passing the value into the inline helper removes the two extra `lwz`
instructions while preserving the retail value lifetime. A local captured
argument produces the same runner code; the shared helper also removes the
duplicate immediate-selection implementation. The runner shrinks from 1,472
to 1,464 bytes; retail is 1,504 bytes, with independent addressing and loop
differences still unresolved.

Only the runner's instruction bytes change. `gameTextSetCharset` remains
exact at 212 bytes, and all other function bodies and allocated non-text
sections remain unchanged. Named data-symbol layouts are preserved, as are
relocations outside the changed runner and its internal jump-table targets.
All 44 previously exact functions remain exact. Unit fuzzy matching increases
from 97.61308% to 97.66155%.

All 16 gametext tests pass, including 402 load scenarios at each of host `-O0`
and `-O2`. The TU and canonical API header pass the formatting check without
additional formatting changes; a rebuild preserves the complete object bytes.
`ninja all_source` and strict `ninja` pass after matching configuration, with
30-second timeouts, and the matching DOL remains byte-identical to retail.
The unit remains `NonMatching`; the checksum uses its retail object.

## Exact renderer initialization (2026-09-07)

`gameTextInitRendererState` now matches all 492 retail bytes. The fallback loop
indexes the native string, definition, and backing-buffer arrays directly. Its
separately staged string/definition pointers had changed the three generated
cursor registers. The final current-buffer lookup uses `gGameTextLastEntry`
after assigning it, reproducing the retail pointer lifetime.

The private inline `gameTextResetFont` owns the repeated font-record reset,
including all three texture slots. The outer initializer walks the four fonts
and calls it. This boundary reproduces the retail allocation of the font cursor,
texture cursor, and inner loop counter. No out-of-line helper is emitted.
All reverse loops remain bounded integer-index loops; no pointer is formed
before an array to drive termination.

Only the initializer's instruction bytes change. Every other function, named
symbol layout, and allocated non-text section remains unchanged. The unit rises
from 42/54 to 43/54 exact functions and from 97.420944% to 97.45126%, adding 492
matched code bytes. No compiler setting or TU boundary changes. The runtime
fixture executes the new production helper as part of its complete initialization
checks; all sixteen gametext tests pass, including both sets of 402 load-lifecycle
scenarios. The unit remains `NonMatching` pending its other eleven functions.

## Shared window-position application (2026-09-07)

The immediate branch of `gameTextSetWindowStrPos` and the queued
`GAMETEXT_COMMAND_SET_WINDOW_POSITION` handler now share the private inline
`gameTextApplyWindowPosition` helper. The queued call captures the window index
and both coordinates before either cursor store. This removes the old second
read of `cmd->arg0` and its repeated address calculation, matching retail's
single argument capture. The signed halfword conversions and store order are
retained. The setter also uses the existing symbolic command ID when queuing.

The helper deliberately indexes the canonical window array. An explicit local
window pointer was tested: it improves the runner less and regresses the exact
immediate setter. Extracting the unrelated per-frame flag-clear loop leaves the
runner's differences unchanged and is not retained.

Against `ee4b8668ed`, `gameTextRun` improves from 91.27128% to 91.79521%, shrinking
from 1,464 to 1,456 bytes. Retail remains 1,504 bytes; independent shared-array
addressing and loop differences are unresolved. The immediate setter retains
all 25 exact instructions. No other function body changes, and all 53 other
functions retain their function-relative relocation targets. The runner's
fourteen affected jump-table targets follow the eight-byte code reduction;
allocated non-text bytes and named data layouts are unchanged.

The TU rises from 97.81967% to 97.8544% fuzzy matching and remains `NonMatching`,
with 44/54 exact functions. All sixteen existing gametext tests, full source
compilation, and the strict retail checksum pass. Those host fixtures cover
resources, load lifecycles, fallback handling, colors, and measurement; the
queued position handler is assessed by its retail instruction comparison.
The source and canonical API header pass the formatter check. Formatting adds
no diff and preserves the complete semantic object.

`ninja all_source` and the strict retail checksum both pass with 30-second
limits. The resulting DOL remains byte-identical to retail; the complete unit
still links its retail object until the remaining functions are recovered.

## Promoted color parameters and parser address expressions (2026-09-07)

This pass builds on the deferred-emission and exact-initialization changes
above. It raises the TU from 97.45126% to 97.61308% fuzzy and from 43 to 44
exact functions, retaining the current compiler profile and source order.

`gameTextSetColor` uses an old-style C definition with `u8` parameters.
Default argument promotion makes this compatible with the public `int`
prototype while preserving the byte types inside the function. This removes
four redundant conversions before the direct byte stores and reproduces all
104 retail bytes. Queued integer fields still receive narrowed channels, and
callers retain their generated bytes. The host color harness explicitly selects
C17 and permits the deprecated definition syntax; its 1,028 cases continue to
check both modes, including out-of-range inputs.

The resource parser derives each following block from its own header and
record sizes. Its message header remains after the four-byte glyph count and
the complete glyph array; it does not overlap the last glyph. Grouping the
string-table extent preserves the separate header-size addition in retail.
Removing the obsolete glyph-pointer local and adjusting declaration order
brings `gameTextFinalizeLoad` from 98.095474% to 99.34673%, with the exact
1,592-byte instruction count. Remaining differences are register operands.
All 360 synthetic compiled-versus-retail PPC comparisons pass, including
texture allocation failures, copy tails, relocated data, and ABI checks.

Only these two function bodies change. Allocated non-text section bytes,
named storage layouts, and normalized data relocation destinations remain
unchanged. The gametext tests, `ninja all_source`, and the strict checksum pass;
both Ninja invocations have 30-second limits. The TU remains `NonMatching`, so
the checksum still uses its retail object. Formatting is recorded separately
and preserves the complete generated object.

## Fixed-point scale commands (2026-09-07)

The scale command's big-endian 16-bit argument encodes 1.0 as `0x100`.
Measurement, rendering, and wrapping now share the private inline
`gameTextDecodeScale`, which converts the signed working integer to float and
divides by `256.0f`. The helper name is reconstructed; the conversion and its
three consumers are evidenced by retail instructions.

MWCC folds the division into multiplication by the same `0.00390625f`
literal already present in the retail pool. Unlike the previous explicit
reciprocal multiplication, this spelling finishes the integer-to-float
conversion before loading the reciprocal. Each consumer's ten-instruction
conversion block now matches retail, including the floating-point registers
and multiplication operand order. An inline helper that retained the old
multiplication was byte-neutral and did not fix the block.

| Function | Before | After |
| --- | ---: | ---: |
| `gameTextMeasureString` | 94.35599% | 94.58253% |
| `textRenderStr` | 97.02047% | 97.21638% |
| `gameTextWrapLines` | 95.55773% | 96.45098% |

Unit fuzzy matching rises from 97.66155% to 97.78159%; all 44 exact functions
remain exact. Only these three function bodies change, with no size changes.
All allocated non-text sections and named-symbol layouts are unchanged. Each
function retains its relocation destinations and counts; only the two literal
load positions within each conversion block move.

The compiled production helper was checked over all 65,536 encoded values at
host `-O0` and `-O2`, with bit-identical results to the previous conversion.
All 16 gametext tests pass. Formatting the TU and canonical API header preserves
the complete object. `ninja all_source` and strict `ninja` pass after matching
configuration with 30-second timeouts, and the matching DOL is byte-identical
to retail. The unit remains `NonMatching`, so its retail object supplies the
matching link while the remaining source differences are recovered.


## System-font glyph-count lifetime (2026-09-07)

`gameTextBuildSystemFontAtlas` captures the selected charset's glyph count once,
uses that value to initialize the system-font metrics, and then copies it into
the independent countdown variable. These two locals describe different roles:
the original count stays fixed while the loop consumes the remaining count.
The capture follows texture allocation, preserving the original callback order.

Retail keeps the initial count in `r3` across the metric stores and copies it
to `r22` afterward. The previous source instead reloaded `charset->glyphCount`.
Capturing directly into the countdown variable removed that reload but moved
the register copy too early. A separate `glyphCount` local retains the retail
lifetime and reproduces the load, narrowing operation, and final register copy.
The intervening stores belong to the separate font-metrics array and do not
change the charset's count.

The function rises from 96.123634% to 96.90909%; the unit rises from 97.78159%
to 97.81967%. Exactly three instruction words change, with the existing
1,088-byte source function size retained against 1,100 retail bytes. Every
other function, all allocated non-text sections, named-symbol layouts, and
relocation records are unchanged. This does not add an exact function.

The 16 existing gametext tests pass, covering neighboring text behavior and
storage layout; they do not execute the atlas builder. The atlas change is
verified directly against the retail instructions and the complete object
diff. Formatting the active TU and canonical API header produces no changes
and preserves the whole object. The unit remains `NonMatching`.

Matching configuration, `ninja all_source`, and strict `ninja` pass with
30-second timeouts (`main.dol: OK`). The matching link continues to use this
unit's retail object.
