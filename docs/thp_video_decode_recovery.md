# THP player and video decoder records and storage

## Player TU and native preparation

`src/main/thp/THPPlayer.c` consolidates the former `n_options.c`, `dll_3e.c`,
`attractmovie.c` and `picmenu.c` fragments. The 21 functions occupy the contiguous
EN text span `80117668..80119458` (7,664 bytes). The shared BSS base, storage
order, contiguous small-data pools and THP player function family support one
TU. The local Mario Kart Double Dash and Pikmin 2 `THPPlayer.c` implementations
corroborate the family and its ordinary globals, including a 16-word aligned
DVD workspace. No direct `THPPlayer` source-name leak was found in `orig/`;
the filename identifies the source lineage, not a recovered literal SFA path.
The former front-end names do not establish these functions' ownership.

With the existing deferred, no-auto-inline optimization profile and the common
game GC/1.3 compiler, SDK-style initialization-first source order emits the
retail reverse function order. The compiler also generates the shared BSS base
from separate globals. No hand-written aggregate overlay, synthetic section,
per-function compiler flags or retail object substitution is needed.

| Offset from the audio buffer | Object | Bytes |
| --- | --- | --- |
| `0x000` | Two audio DMA buffers | `0x500` |
| `0x500` | Three spent-texture message slots | `0xC` |
| `0x50C` | Spent-texture queue | `0x20` |
| `0x52C` | Preparation-ready queue | `0x20` |
| `0x54C` | Alignment before DVD workspace | `0x14` |
| `0x560` | Sixteen `u32` DVD workspace words, aligned to 32 bytes | `0x40` |
| `0x5A0` | Player | `0x1A8` |

Initialization now clears the player and initializes the actual queue and its
three messages directly. It previously obtained their addresses by adding
constants to the audio buffer, whose declared size incorrectly included the
message array. The preparation queue was also falsely sized as `0x34` bytes;
the trailing `0x14` bytes are workspace alignment, not queue fields.

Preparation now uses the existing `AttractMoviePlayer` fields instead of a
padded `AttractMovieControl` overlay. Size and member-offset assertions beside
the shared record check the retail layout. Modeling the DVD workspace as
`u32[16]` also lets MWCC keep the first offset-table word across player stores,
recovering the exact load sequence without aliasing unrelated objects.
`movieLoad` takes a boolean in-memory flag, and preparation receives an
`OSMessage` rather than an integer-shaped pointer. Its first-frame address uses
full-width `size_t` arithmetic: this preserves the retail add-then-subtract
order without creating an intermediate pointer outside the movie allocation.
Parenthesizing the offset subtraction changes the retail load/register order.
The final `AIInitDMA` conversion remains the SDK's 32-bit hardware-address API.

`tools/test_thp_player_native.py` executes seven production lifecycle functions
with their real shared record definitions and storage declarations. Its 41
scenarios cover initialization/callback restoration, THP headers and components,
DVD failures, streaming and in-memory preparation, frame-table offsets, queues,
and ready/failure messages. Both `-O0` and `-O2` pass ASan and UBSan with pointers
above 4 GiB. Separate negative controls reject the old player-base offset,
message-tail alias, truncated first-frame pointer and reversed frame-size words.
The fixture preserves retail quirks: an unknown component does not close the
file, and preparation does not check thread-creation return values.

All five configured retail versions match all 21 functions and all 2,201 data
bytes at 100%. Every other source object is byte-for-byte unchanged. The full
inventories retain only the pre-existing TRK exception-carving and MusyX
discarded-data report artifacts. Every `all_source` build and strict source
link passes; each output DOL equals its verified original byte for byte.
Regional projection confirms the combined THP windows; unrelated conservative
projection changes were discarded in favor of already-verified boundaries.

## Video decoder record

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
The preparation caller now lives in the consolidated player TU described above
and retains the full native pointer width at that boundary.

At the earlier decoder-recovery checkpoint, all four verified targets preserved
every function's instruction bytes, all allocated section bytes and sizes, and all relocation destinations. The only
source-object symbol change is the message-storage rename. The five named BSS
objects agree with their retail objects in section, offset and size. Full
function reports and aggregate measures are unchanged; this is source and
storage recovery, not additional matching-byte credit.

That checkpoint passed all four `all_source` builds and the strict EN retail
checksum within the 30-second limit. Unrelated source-object hashes, including the preparation
caller and audio decoder, are unchanged. Formatting is reviewed separately.
