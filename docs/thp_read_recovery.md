# THP reader buffers and queue ownership

`src/main/thp/THPRead.c` owns the streamed attract-movie reader. Its public queue
API carries pointers to the existing eight-byte `AttractMovieReadBuffer` record:
a destination pointer at offset zero and a frame number at offset four.
`include/main/thp_read.h` now owns these declarations. The audio decoder, video
decoder, and player initialization use the same typed contract.

## Retail evidence

EN `THPRead_Reader` (`80119520..80119618`) receives a free buffer, reads DVD data
into its pointer, stores the frame number at `+4`, and posts the record to
`gPicMenuReadedBufferQueue`. The next frame size comes from the first word of the
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

The private layout type names the offsets used by the retail shared base. It is
not instantiated: the globals and their declaration order remain separate. The
message arrays already existed in source; their names now identify the previously
anonymous `0x78` bytes in all four verified retail symbol configs. The stack's
former `Area` name now describes its actual role.

The read-buffer count is defined beside `AttractMoviePlayer`, whose ten records
supply the queue. No count or object size is inferred only from a neighboring gap.

## Source lineage and code generation

The local Sunshine `src/THPPlayer/THPRead.c` reference has the same three queues,
three ten-entry message arrays, stack, thread, and reader flow. Its differing
function order and signed locals are not imported. SFA's retail calls and active
compiler output remain the authority for the recovered layout and expressions.

Direct references to the separate globals increased the reader from 248 to 264
bytes and thread creation from 156 to 176 bytes. The layout view preserves the
shared base without those extra instructions. The reader's OS receive temporary
also remains `OSMessage`: making that temporary a record pointer added one
instruction. The typed record begins immediately after receipt, and the public
queue interface is typed. These are code-generation constraints, not evidence
that the original source used a layout struct or a particular local spelling.

## Validation

All four input DOLs pass their configured SHA-1 checks: EN, EN rev1, JP, and PAL
rev1. Full source builds preserve every function instruction and allocated section
byte. The only source-object symbol change is the stack rename; relocation
changes refer to that same renamed object at the same offsets. All other source
objects are byte-identical, including all three edited callers. The eight named
BSS objects agree with the retail section offsets and sizes in every version.

Function reports and aggregate match scores are unchanged. The reader's 716 code
bytes remain exact in every version. EN remains fully exact with 5100 data bytes;
EN rev1 and JP retain their existing complete status. PAL retains its existing
`.sbss` mismatch: the regional projection includes an extra four-byte trailing
word named `lbl_803DF04C`, while source emits only the four-byte thread-created
flag. The regional projector's single-word gap folding is separate from this
reader recovery; no split extent is changed here.

The strict EN matching link and retail checksum pass. Secondary builds validate
projected objects, not full regional DOL relinks.
