# Audio DSP voice allocation prefix

`main/audio.c` now matches completely in all five configured retail versions.
The remaining EN rev1 and PAL difference was `_audioAlloc`, not a MusyX compiler
profile or an audio TU boundary.

At `0x8000A1D8`, EN v1.0 and JP have a 40-byte allocator that calls
`mmAlloc(size, 11, 0)`. EN rev1, PAL v1.0, and PAL rev1 instead have a 72-byte
allocator. Their extra branch compares the request against `0x2DC0`, adds
`0x100` to the allocation size, and adds another `0x100` to the returned pointer.
Other request sizes take the ordinary allocation path.

The request corresponds to the DSP voice array: `audioInit` passes 48 voices to
`sndInit`, and `salInitDspCtrl` allocates `salNumVoices * sizeof(DSPvoice)` through
`salMalloc` and the game's allocation hook. The retail multiply uses stride
`0xF4`, matching the existing asserted `DSPvoice` layout: `48 * 0xF4 = 0x2DC0`.
The source expresses the comparison using that type and the voice-count constant
shared with `sndInit`. The hook itself still selects by size, not by caller.

The purpose of the prefix remains unknown. Retail does not test allocation
failure before adding the prefix, and `audioFree` still passes its pointer
straight to `mm_free` in every version. The reconstructed MusyX shutdown path
also passes `dspVoice` directly through `salFree`. No compensating subtraction
has been introduced, and this recovery does not claim to explain that behavior.

## Validation

Each original DOL was checked against its configured SHA-1. Objdiff reports all
38 audio functions and all 5,708 data bytes exact in every version: 9,948 code
bytes in EN v1.0/JP and 9,980 in EN rev1/PAL. The latter three each gain one exact
72-byte function and a completed source unit; their matching manifests now
include `main/audio.c`.

All five `all_source` builds and native strict retail checksum targets pass.
Independent links using retail objects throughout, then substituting only the
audio source object, also reproduce each original DOL exactly. EN v1.0 and JP
source objects are byte-identical to the baseline, as are every other source
object in all five versions. Audio's allocated non-code bytes, symbol positions,
and relocations are unchanged; the added branch renumbers three anonymous
literal symbols in EN rev1/PAL without moving their storage.
