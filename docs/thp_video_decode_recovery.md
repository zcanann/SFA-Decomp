# THP video decoder records and storage

The video decoder now passes the existing eight-byte `AttractMovieReadBuffer`
through both streaming and in-memory paths. The in-memory path previously kept
only a local pointer and wrote the frame number through `*(&cur + 1)`. Retail
EN `AttractMovieVideo_DecoderForOnMemory` instead presents a clear record: it
stores the data pointer at stack offset eight, stores the frame number at twelve,
and passes the address at eight to `AttractMovieVideo_Decode`.

A native record reproduces every instruction when its pointer is initialized
before the frame counter. Initializing the counter first exchanges two
instructions; that form was rejected. The shared read-buffer definition now
asserts its size and both member offsets. The decode function and its streaming
caller use typed read-buffer pointers, preserving the unsigned frame-number
view used in modulo arithmetic.

Local Sunshine and Mario Kart Double Dash THP implementations also construct a
`THPReadBuffer` for their in-memory decoders. They corroborate this source shape,
but their player layouts and scheduling details are not substituted for SFA's.
SFA's existing audio decoder already uses the same native record. The active
retail stack accesses establish the eight-byte size used here.

## Message buffers and the BSS base

`gAttractMovieVideoMessages` replaces the misleading thread-area name and
24-byte anonymous array. It contains two arrays of three `OSMessage` slots.
`CreateVideoDecodeThread` supplies the first array to the decoded-texture queue
and the second to the free-texture queue. These roles and capacities come from
the retail `OSInitMessageQueue` calls, not from dividing an unexplained gap.

The TU still defines its message storage, queues, stack and thread as separate
globals. A private layout view names the offsets used by the retail shared-base
accesses without merging those objects or changing their declaration order:

| BSS offset | Object | Size |
| --- | --- | --- |
| `0x0000` | Decoded messages, then free messages | `0x18` |
| `0x0018` | Decoded-texture message queue | `0x20` |
| `0x0038` | Free-texture message queue | `0x20` |
| `0x0058` | Video decode thread stack | `0x1000` |
| `0x1058` | Video decode thread | `0x310` |

The private view is asserted through its total `0x1368` bytes. Thread creation
now expresses the stack top as the stack offset plus its size; the equal thread
address is passed separately as the thread object. The existing source stack
now has its own retail symbol at EN `803A7348`, backed by the 4,096-byte
`OSCreateThread` stack contract and the following thread at `803A8348`.
The canonical decoder header owns message storage and public declarations;
`CreateVideoDecodeThread` takes an optional data pointer instead of an integer.
The preparation caller retains its codegen-proven integer address calculation
and casts explicitly at that boundary.

All four verified targets preserve every function's instruction bytes, all
allocated section bytes and sizes, and all relocation destinations. The only
source-object symbol change is the message-storage rename. The five named BSS
objects agree with their retail objects in section, offset and size. Full
function reports and aggregate measures are unchanged; this is source and
storage recovery, not additional matching-byte credit.

All four `all_source` builds and the strict EN retail checksum pass within the
30-second limit. Unrelated source-object hashes, including the preparation
caller and audio decoder, are unchanged. Formatting is reviewed separately.
