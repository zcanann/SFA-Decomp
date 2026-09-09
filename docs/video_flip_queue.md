# Video flip queue storage

The frame submission path now shares `VideoFlipToken` through
`include/main/video_flip.h`. `videoInit` creates a ten-entry queue with
12-byte elements, and `GXFlush_` writes all three words before enqueueing:

| Offset | Recovered field | Evidence |
| --- | --- | --- |
| `0x0` | `fifoWritePointer` | Written from `GXGetFifoPtrs`' write pointer; callbacks pass it to `GXEnableBreakPt`. |
| `0x4` | `reserved` | Producer writes zero; no consumer reads this word. Its intended role remains unknown. |
| `0x8` | `frameBuffer` | Written from `renderFrameBuffer`; breakpoint callback compares it with `displayFrameBuffer`. |

The queue backing array is ten native tokens, retaining its 120-byte size.
The producer and all three callback consumers use the same definition. Field
and total-size assertions keep the recovered contract beside the type. Callback
ordering, display-flip state, depth-read processing and interrupt masking are
unchanged.

The separate queue that sleeps the rendering thread is an eight-byte
`OSThreadQueue`. Its previous one-byte declaration plus the adjacent local
`sPiUnused4` placeholder represented the head and tail as unrelated storage.
Retail `OSInitThreadQueue` at EN `80245D78` writes words at offsets four and
zero; `OSSleepThread` and all three wakeup paths receive this same address.
The source object placed the placeholder at `.sbss + 0x58`, four bytes after
`gVideoFlipWaitQueue` at `+0x54`. No code referenced the placeholder directly.
The next real object, `displayFrameBuffer`, begins eight bytes after the queue.

| Verified target | Thread queue | Following display pointer |
| --- | --- | --- |
| EN v1.0 | `803DCCC4` | `803DCCCC` |
| EN rev1 | `803DD944` | `803DD94C` |
| JP | `803DCDE4` | `803DCDEC` |
| PAL rev1 | `803DE684` | `803DE68C` |

The definition and regional symbol extents now describe the complete queue,
and callers no longer cast a byte's address to `OSThreadQueue*`. This corrects
the recovered storage contract without adding storage: allocated section sizes
and bytes, every function's instructions and relocation destinations, and all
neighboring symbol positions are preserved. The only owning-object symbol
changes are the queue's size and removal of the tail placeholder. The video
initialization object remains byte-identical.

A constant-pool investigation preceded this recovery. Extracting the timing
clamp into a live inline helper did not move its literal pool under the current
compiler; extracting the entire frame-step block also regressed code. Neither
experiment is retained, and the video pool remains unresolved. This recovery
claims no match-score increase.

All four `all_source` builds and the strict EN retail checksum pass within
the 30-second limit. Full function reports and aggregate measures are unchanged;
all other source-object hashes are unchanged. Formatting checks pass for the
active source and canonical header without a separate formatting diff.

## Frame-timing constant pool (2026-09-09)

The earlier negative inline experiments are superseded by three small, called
static helpers for the time-delta clamp, inverse delta and fractional frame
remainder. With the common automatic-inlining setting, GC/1.3 inlines all three
into `waitNextFrame` without changing its instructions. Their emitted bodies
establish the retail literal order before viewport setup; the linker discards
those bodies. An explicit `inline` helper did not establish that order, and a
single larger ordinary helper retained a call and regressed code. This is a
plausible source reconstruction, not proof of the original helper names.

Only the TU's `-inline noauto` override is removed. Its compiler and remaining
optimization settings are unchanged. The anonymous `.sdata2` pool shrinks from
56 bytes to the exact retail 52 bytes: zero, six, one, 0.1, unsigned-conversion
bias, then the viewport and elapsed-time literals. No named duplicate constants
or artificial section placement are needed.

Cross-version verification also exposed two existing behavior differences:

| Target | Viewport-height load | Copy filter |
| --- | --- | --- |
| EN v1.0 | `80049D74`: `lhz r0,8(r4)` (`xfbHeight`) | Conditional |
| EN rev1 | `80049EF0`: `lhz r0,6(r4)` (`efbHeight`) | Conditional |
| JP | `80049D94`: `lhz r0,8(r4)` (`xfbHeight`) | Conditional |
| PAL v1.0 | `80049F8C`: `lhz r0,6(r4)` (`efbHeight`) | Always custom |
| PAL rev1 | `80049F8C`: `lhz r0,6(r4)` (`efbHeight`) | Always custom |

The height loads were read directly from each hash-verified input DOL. Both PAL
`setDisplayCopyFilter` bodies at `8004A5EC` contain thirteen instructions and
unconditionally pass `GX_TRUE` with `gDispCopyFilterWeights`; the other targets
retain the progressive/field-rendering test. The source records these proven
differences while sharing the timing helpers across all five targets.

PAL rev1 additionally had five EN-address labels attached to unrelated `.sdata`
words at those same numerical addresses. Its retail r13 base is `803E4B40`;
the stores in `videoInit` establish the actual `.sbss` destinations below.
The video state remains owned by `pi_dolphin.c`, with no storage or split changes.

| EN source label | PAL rev1 store | PAL rev1 destination |
| --- | --- | --- |
| `lbl_803DCCE0` | `80049DF4`: `stw r0,-25768(r13)` | `803DE698` |
| `lbl_803DCCF4` | `8004A4A0`: `stw r0,-25748(r13)` | `803DE6AC` |
| `lbl_803DCCF8` | `8004A510`: `stb r3,-25744(r13)` | `803DE6B0` |
| `lbl_803DCCFC` | `8004A50C`: `stw r0,-25740(r13)` | `803DE6B4` |
| `lbl_803DCD00` | `8004A504`: `stb r3,-25736(r13)` | `803DE6B8` |

The unrelated regional words retain their extents and opaque identities under
`palRev1Data_<address>` names. Objdiff normalized these stores as exact even
before the correction; the source-substitution link exposed ten differing bytes
across the five instructions. The small-data audit had no uniquely anchored
whole-function result for this unit, so these mappings use the complete retail
`videoInit` comparison and its independently established r13 base.

Final direct objdiff reports have all ten functions and all 92 data bytes exact
in each target. EN v1.0 and JP retain their ten already-exact functions; EN rev1
gains `videoInit`, and both PAL versions gain `videoInit` and
`setDisplayCopyFilter`. Total text is 3,832 bytes in EN/JP and 3,780 in PAL.
Each target gains 52 matched data bytes and one completed source unit.

All five `all_source` builds, all-retail control links, video-only source
substitution links and native strict checksum targets pass. The three emitted
helper bodies are absent from every final source ELF. Every other source object
is byte-identical to its baseline; other allocated data sections and global data
symbol layouts in the video object are unchanged. Formatting the active source
and `video_flip.h` produces no changes and passes the strict formatting check.
