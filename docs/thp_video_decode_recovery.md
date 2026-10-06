# THP player and decoder records and storage

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

## Video thread globals and shared BSS base

The decoder's queues, thread, stack and message arrays are separate globals.
`AttractMovieVideoDecodeLayout` formerly treated them as one aggregate reached
from the message-storage address. The retail offsets were right, but that
cross-object pointer arithmetic relied on the GameCube linker layout and could
not work reliably in a native build. Thread creation, suspension, message
receives and message sends now address their actual owning globals directly.

The local Mario Kart Double Dash `THPVideoDecode.c` has the same six ordinary
BSS definitions and creation-first function order. Using that declaration order
with the existing deferred/no-auto-inline profile makes the common game GC/1.3
compiler generate the retail BSS base and reverse function order naturally.
All eight functions reproduce their original instructions. No layout overlay,
manual section placement or compiler-version exception remains in this TU.
Foxhollow independently uses direct queue/thread references and the actual
stack end; its native fixes corroborate these ownership relationships.

| Retail BSS offset | Object | Bytes |
| --- | --- | --- |
| `0x0000` | Three decoded-texture messages | `0xC` |
| `0x000C` | Three free-texture messages | `0xC` |
| `0x0018` | Decoded-texture queue | `0x20` |
| `0x0038` | Free-texture queue | `0x20` |
| `0x0058` | Video decode thread stack | `0x1000` |
| `0x1058` | Video decode thread | `0x310` |

Each `OSInitMessageQueue` call establishes the relevant three-message capacity.
The former two-array message record has been replaced by those two arrays;
`OSMessage` elements can grow with native pointer width. The three small-data
words keep their retail order: thread-created, preparation-ready, idle-frame
count. The private thread, queue and state symbols now use the video decoder's
namespace instead of the unrelated `picmenu` name. All five symbol configs and
stack force-active entries use the new names.

The component loop retains a byte cursor rooted in `AttractMoviePlayer` and
uses its canonical `offsetof` to load component kinds. A direct array pointer
changes two instructions; indexing the canonical array removes an instruction
and changes register allocation. This cursor remains within the real player
record and does not overlay separate objects. The in-memory decoder uses the
canonical `initReadSize` and `movieData` members in place of legacy union aliases.

`tools/test_thp_video_native.py` compiles the entire production TU with native
player records and deliberately independent host OS objects. Its 24 scenarios
cover both thread-entry choices, creation failure, guarded start/cancel, message
flags and ownership, component traversal, decode failure and preparation-ready
messages, streaming catch-up, in-memory frame stepping, looping, and forced
final-frame decoding. They pass at `-O0` and `-O2` with ASan/UBSan and addresses
above 4 GiB. Separate negative controls reject a restored cross-object queue
offset, a truncated thread argument, swapped message storage, and skipping the
last non-looping frame.

Across all five configured retail versions, the complete decoder matches all
eight functions (1,276 code bytes) and all 4,980 data bytes at 100%. Every other
source object is byte-for-byte unchanged by this decoder recovery. Full reports
retain only the existing TRK exception-carving and MusyX discarded-data artifacts.
All five `all_source` builds and strict source links pass, with output DOLs
byte-identical to their verified originals. Formatting is checked separately
against every source-object hash.

## Audio decoder ownership and native buffers

`src/main/thp/THPAudioDecode.c` replaces the misleading `dll_3b.c` helper name.
Its eight functions occupy EN `8011730C..80117668`; this is the THP audio thread
and its buffer queues, not a numbered front-end DLL. The local Mario Kart
Double Dash `THPAudioDecode.c` corroborates the source family and declaration
order. `tools/orig/source_leaks.py --search THPAudioDecode` finds no direct
source-name leak, so the new filename records lineage rather than a literal
recovered SFA path. Double Dash's six-buffer capacity and audio-track selection
are not imported: SFA's creation calls specify three buffers and its decoder
passes the audio component directly to `THPAudioDecode`.

The former aggregate layout joined unrelated message arrays, queues, stack and
thread storage. It also gave `OSThread` an unexplained 16-byte tail. Ordinary
globals now own each object, and every operation addresses its actual queue,
thread or stack. The retail creation function establishes these offsets:

| Offset from EN `803A4448` | Object | Bytes |
| --- | --- | --- |
| `0x0000` | Three decoded-audio messages | `0xC` |
| `0x000C` | Three free-audio messages | `0xC` |
| `0x0018` | Decoded-audio queue | `0x20` |
| `0x0038` | Free-audio queue | `0x20` |
| `0x0058` | Audio decode thread stack | `0x1000` |
| `0x1058` | Audio decode thread | `0x310` |

The thread ends at EN `803A57B0`; the next TU's audio DMA buffer starts at
`803A57C0`. `THPPlayer.c` already emits a BSS section aligned to 32 bytes because
of its DVD workspace. Recording that existing alignment in the split config
accounts for the intervening 16 bytes without inventing thread fields or a
padding object. The same gap appears in all five versions. Regional projection
confirms both TU windows and all seven audio storage symbols; unrelated
projection changes are left out.

SDK-style creation-first source order and the deferred/no-auto-inline profile
already used by the other THP TUs reproduce all eight functions under the common
game GC/1.3 compiler. The compiler generates the shared BSS base from the separate
globals. A private typed inline `PopFreeAudioBuffer` replaces the one-element
pointer array in the component decoder. The analogous helper exists in the
Double Dash family. In SFA, its typed result preserves retail register allocation
while leaving the component loop as ordinary indexing into `compInfo.mFrameComp`.
The in-memory path uses the canonical `initReadSize` and `movieData` members.

`include/main/audio_decode_thread.h` owns the public API. The old mixed header,
aggregate types and unimplemented PC helper declarations are removed. Its unrelated
`TitleMenu_initialise` declaration moves to the existing title-menu header, and
the two direct consumers use their actual owner headers.

`tools/test_thp_audio_native.py` runs the complete production TU with native
game records and independent host OS objects. Its 28 scenarios cover both thread
entry points, creation failures and priorities, guarded start/cancel, queue
ownership and flags, component traversal, sample counts and frame tags, streaming
handoff, variable frame sizes, nonzero initial frames, looping, one-frame movies
and continuation after suspension. They pass at `-O0` and `-O2` with ASan/UBSan,
pointers above 4 GiB and output canaries. Five separate negative controls reject
a cross-object queue offset, wrong stack end, narrowed frame pointer, advancement
by the next frame size and a wrong frame tag. Retail quirks remain: a frame
without audio consumes a free buffer without posting it, repeated audio
components post the same buffer, and resuming a one-frame non-looping movie
decodes that frame again.

All five versions match all eight audio functions (860 code bytes) and all
4,972 owned data bytes at 100%. The 16 alignment bytes are no longer counted as
thread storage. Every other source object is byte-for-byte unchanged. Full
reports, with completion metadata removed, retain only the pre-existing TRK
exception-carving and MusyX discarded-data artifacts. All five `all_source`
builds and strict source links pass; each DOL equals its verified original.
The existing player, reader and video native tests also pass. Formatting is
validated separately against every source-object hash.
