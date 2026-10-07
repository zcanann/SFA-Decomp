# THP reader buffers and queue ownership

`src/main/thp/THPRead.c` owns the streamed attract-movie reader. Its public queue
API carries pointers to the existing eight-byte `AttractMovieReadBuffer` record:
a destination pointer at offset zero and a frame number at offset four.
`include/main/thp_read.h` now owns these declarations. The audio decoder, video
decoder, and player initialization use the same typed contract.

## Retail evidence

EN `THPRead_Reader` (`80119520..80119618`) receives a free buffer, reads DVD data
into its pointer, stores the frame number at `+4`, and posts the record to
`gAttractMovieReadDvdQueue`. The next frame size comes from the first word of the
current frame. The file offset advances by the current frame size; the loop flag
resets that offset to the movie-data start after the final frame.

The consumers establish the three queue roles:

- `InitAllMessageQueue` supplies ten `player->readBuffer` records to the free queue.
- The DVD reader moves records from the free queue to `ReadedBuffer`.
- With audio present, `AudioDecoder` decodes a record from `ReadedBuffer` and posts
  it to `ReadedBuffer2`. The video decoder consumes that second queue.
- Without audio, the video decoder consumes `ReadedBuffer` directly.
- After decoding or deliberately skipping a video frame, the video decoder
  returns the record to the free queue.

All these transfers block. The API retains the established `ReadedBuffer` names;
its header explains the distinction between the two filled-buffer queues.

`CreateReadThread` (`80119688..80119724`) proves a 4096-byte stack and three
message arrays of ten entries each. Relative to the stack base `803A5F08`:

| Offset | Storage | Size |
| --- | --- | --- |
| `0` | Reader stack | `0x1000` |
| `0x1000` | `OSThread` | `0x310` |
| `0x1310` | Audio-decoded message slots | `0x28` |
| `0x1338` | DVD-filled message slots | `0x28` |
| `0x1360` | Free message slots | `0x28` |
| `0x1388` | Audio-decoded queue | `0x20` |
| `0x13A8` | DVD-filled queue | `0x20` |
| `0x13C8` | Free queue | `0x20` |

The globals now use direct references throughout the reader. The former private
`AttractMovieReadThreadLayout` overlaid these independent objects by starting
from the stack address. Its offsets described the retail linker layout, but
could not establish valid cross-object pointer arithmetic in a native build.
The overlay and its padded type are removed. Each queue uses its actual
message array; each thread operation uses the actual `OSThread`, and creation
passes the stack's own end.

All nine owned symbols now use the `gAttractMovieRead` namespace. Queue and
message names distinguish DVD-filled, audio-decoded and free buffers. The five
retail symbol configs preserve every original address and size, and the three
message-array force-active entries follow their renamed definitions. The
read-buffer count remains beside `AttractMoviePlayer`, whose ten records supply
the queue. No count or object size is inferred only from a neighboring gap.

## Source lineage and code generation

The local Sunshine and Mario Kart Double Dash THP reader implementations have
the same three queues, three ten-entry message arrays, stack, thread and reader
flow. Double Dash also puts the definitions in the order that produces SFA's
retail BSS and declares thread creation before the reader and queue helpers.
Foxhollow independently replaces the stack-relative overlay accesses with
direct queue and thread references.

That declaration order, with the existing deferred/no-auto-inline optimization
profile and the common game GC/1.3 compiler, generates the shared BSS base
naturally and emits the functions in retail reverse order. All eight functions
remain exact. Earlier direct-reference experiments without deferred compilation
increased the reader from 248 to 264 bytes and creation from 156 to 176 bytes;
those results do not require keeping an overlay. The current reader is 248
bytes and creation is 156 bytes, using ordinary globals and no synthetic section
placement or compiler-version exception.

The receive temporary remains an `OSMessage`, followed immediately by the typed
read-buffer pointer. The public queue API keeps its established SDK spellings
and typed records; callers do not need a new interface or local declarations.

## Validation

`tools/test_thp_read_native.py` compiles the complete production TU with the real
game record definitions and independent host OS objects. Its 25 scenarios cover
thread creation/failure and priorities, guarded start/cancel, all four queue API
functions, message flags and ownership, variable frame sizes, nonzero start
frames, one-frame movies, looping, 32-bit file-position wrap, DVD errors, short
and other mismatched read results, and continuation after suspension. The
fixture keeps record pointers above 4 GiB and checks buffer canaries. Both `-O0`
and `-O2` pass ASan and UBSan. Separate negative controls reject the old queue
overlay, a wrong message array, a narrowed buffer pointer, advancement by the
next frame size, and sending the ready-failure message for the wrong frame.

The tests preserve retail error behavior: only a `-1` DVD result sets `dvdError`,
any mismatched read count suspends the thread, and only the first requested
frame sends `PrepareReady(0)`. Resuming after an error continues by posting that
same buffer; resuming after the non-looping final frame continues reading.
Thread suspension, rather than an implicit return from the reader, is the stop.

All five input DOLs pass their configured SHA-1 checks. The complete reader
matches all eight functions (716 code bytes) and all 5,100 data bytes at 100% in
EN, EN rev1, JP, PAL and PAL rev1. Every other source object is byte-for-byte
unchanged. Full inventories retain only the pre-existing TRK exception-carving
and MusyX discarded-data report artifacts. All five `all_source` builds and
strict source links pass, and each output DOL equals its original byte for byte.
Formatting is checked separately against every source-object hash.
