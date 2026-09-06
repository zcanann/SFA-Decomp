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
agree with retail, including:

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
