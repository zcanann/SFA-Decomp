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
