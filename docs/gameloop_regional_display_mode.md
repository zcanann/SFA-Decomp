# Regional display-mode prompt and DVD error result

The later [TU boundary audit](gameloop_tu_recovery.md) reunifies the three game-loop
fragments and supersedes their completed-unit status below. These results record
the preceding regional behavior recovery.

The EN v1.0 and JP display-mode prompt selects progressive scan. Both PAL
releases instead select PAL 50 Hz or EURGB60 interlaced output. The common
source now preserves those binary-backed differences without changing compiler
profiles or translation-unit boundaries.

## Retail evidence

All five input DOLs were checked against the SHA-1 in their version configs.

`dvdCheckError` is 556 bytes in EN v1.0 and JP and returns no value. In EN rev1
and both PAL releases it is 568 bytes: the error-message path ends with
`li r3,1`, followed by a branch over the no-message path's `li r3,0`.
The latter versions therefore return whether an error message was shown.
Their shared declaration and implementation now expose this result.

PAL calls this check before rendering each display-mode prompt frame. An error
moves the message from Y=110 to Y=190 and subtracts 64 from its RGB intensity.
The yes/no entries use `gameTextShowAt` with Y=246. EN and JP retain their
existing string-position calls; EN rev1 retains the same prompt behavior even
though its DVD checker has the newer return contract.

PAL selects `GXEurgb60Hz480IntDf` for yes and a game-owned render-mode record for
no. It saves the choice with `OSSetEuRgb60Mode` and sets display-copy Y scale to
`xfbHeight / efbHeight`. The SDK setter was unnamed at PAL v1.0 `802460CC` and
PAL rev1 `80246204`. Both retail bodies mask the input's low bit, shift it to
bit 6, update the SRAM `ntd` byte at offset 0x11, and unlock SRAM with the correct
changed flag. This agrees with the SDK implementation in the read-only Pikmin 2
reference project and the existing `OSRtc.h` declaration.

## Render-mode ownership

The same 60-byte `GXRenderModeObj` occurs after the 80-byte packed reset-message
block and before the memory-card dialog jump table in three versions:

| Version | Render-mode address |
| --- | --- |
| EN rev1 | `802CB030` |
| PAL v1.0 | `802CBB28` |
| PAL rev1 | `802CBC68` |

It specifies PAL interlace, framebuffer width 640, EFB height 480, XFB height
528, VI origin (40,23), VI dimensions 640x528, double-field output, no AA, twelve
(6,6) samples, and vertical weights `{7,7,12,12,12,7,7}`. The records are
byte-identical across those three verified DOLs. The EFB height and weights
differ from the SDK's stock `GXPal528IntDf`.

EN rev1 had incorrectly combined this record with its preceding message block
into a 140-byte symbol. Its config now describes the two actual objects; the
existing TU section extent is unchanged. PAL already had the correct 60-byte
boundary. The source emits `gGameLoopPalRenderMode` in its evidenced declaration
order, preserving the packed message block.

EN rev1 does not reference this PAL mode. A source-only link initially discarded
it, while the all-retail control kept it. Explicitly retaining this one symbol
in EN rev1's existing `force_active` list restores the exact retail DOL; no
checksum or section-placement workaround was used.

## Results and validation

- `main/fileio.c`: all six functions and all 124 data bytes now match in all
  five versions. EN rev1 and each PAL release gain the 568-byte `dvdCheckError`
  match (97.85211% to 100%) and a completed source unit.
- `main/gameloop.c`: EN rev1's eleven functions were already exact. Recovering
  the missing mode makes its full 508 data bytes exact and completes that unit.
- Both PAL game-loop units improve from 82.53737% to 99.73309%; their 968-byte
  prompt improves from 59.44628% to 99.380165%. All ten other functions remain
  exact, and all 492 data bytes now match. The remaining prompt differences are
  register assignments, so these two units remain NonMatching.
- Recovering the missing 60-byte mode makes the entire 220-byte `.data` section
  exact in each affected version. This is a 220-byte matched-data gain per
  report, not 220 bytes of newly recovered source data.
- EN v1.0 and JP source objects for both files are byte-identical to their
  previous builds. Across all five versions, every other source object remains
  byte-identical despite rebuilding the shared-header consumers.
- Every version passes `ninja all_source` and its native matching-link retail
  checksum. Independent all-retail and selected-source links also reproduce
  each verified DOL: both units in EN, EN rev1 and JP; file I/O alone in PAL.
  Only those verified exact regional units were added to progress manifests.

Local declaration/type/lifetime probes did not finish the PAL register match;
none were retained. No compiler flags or artificial source splits were added.
