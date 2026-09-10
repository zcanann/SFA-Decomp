# Game-loop translation-unit recovery

The three former files `gameloop.c`, `gameloop_buttonobj.c`, and
`gameloop_main.c` are now one `src/main/gameloop.c`, in retail function order.
This corrects an optimization-driven split and recovers the PAL boot path and
its memory-allocation contract. It deliberately leaves the merged TU
NonMatching while its real storage layout remains incomplete.

## Boundary evidence

Commit `361e41be1b` introduced the two extra files to enable peephole optimization
for `removeButtonObject`. Its own description states that the carve was selected
by per-function compiler results. Partitioning the strings, jump tables and BSS
at convenient boundaries did not establish separate original TUs.

Retail `checkReset` also materializes the address of the first file's
80-byte version/reset metadata block, then uses constant offsets to read the
last file's diagnostic strings. Those offsets cross both proposed code cuts.
The extra PAL render-mode record shifts them by 60 bytes in EN rev1 and PAL.
This is evidence of a shared compiler data base, rather than three independently
compiled files with the reconstructed cross-array C accesses.

The current GC/1.3 game profile compiles all 41 EN functions exactly in a
straight concatenation, with no optimization exception for the button-object
helpers. Both artificial cuts were removed in all five version configs. The
outer EN text extent remains `8001F54C..80021370`; no neighboring code was moved.
`source_leaks.py` and `source_matrix.py` found no retail `main.c` source tag for
this span, so the existing `gameloop.c` path is retained rather than upgrading
the debug-side filename hint to source truth.

The regional projection tool was run with `--write` for all four secondary
targets. Its conservative output rejected the merged window in EN rev1/PAL and
also proposed unrelated symbol changes. Those proposals were reviewed and not
adopted. The final regional spans combine the already verified three windows;
they retain their established outer boundaries and region-specific data.
The PAL unsigned-to-float conversion bias is now explicitly owned by the merged
TU. Four trailing `.data` alignment bytes in EN rev1/PAL remain an automatic
gap after the existing 16-byte finished-init message record.

## Diagnostic source recovery

The previous C used `sGameLoopResetMessages + 0xd0`, etc., to access a different
array. Besides crossing the declared 80-byte object, these EN offsets selected
the wrong bytes in the versions with the extra 60-byte render-mode record.

`GameLoopDiagnosticMessages` now describes the existing packed 204-byte backing
block. `checkReset` uses that block directly, preserving all string bytes and
padding without manufacturing regional offsets or splitting the strings into
separate named constants. Every message and offset was checked in all five
hash-verified DOLs:

| Field | Offset | Width |
| --- | --- | --- |
| setBitsDuringLoad | 0 | 80 |
| resetPressed | 80 | 28 |
| resetNow | 108 | 24 |
| audioQuit | 132 | 20 |
| gxFlush | 152 | 20 |
| viFlush | 172 | 16 |
| resetDefault | 188 | 16 |

The correct local data base changes `checkReset` to 99.971% in EN/JP; it was
already at that score in the secondary versions. This is an intentional match
regression in EN/JP to remove invalid cross-array addressing. The original
version/reset metadata remains explicitly retained in every link config.

## PAL boot and save-buffer contract

Both PAL releases initialize video with `gGameLoopPalRenderMode`, omit the
progressive-scan reset setup, and offer the display-mode dialog if EURGB60 is
saved in SRAM or B is held. They do not preserve an extra byte through
`OSSetSaveRegion` before the dialog.

The unnamed getter at PAL v1.0 `8024605C` and PAL rev1 `80246194` is
`OSGetEuRgb60Mode`: both retail bodies read SRAM `ntd` at offset 0x11 and return
bit 6. This complements the already recovered setter. No SDK compiler profile
was changed.

The PAL dialog state is a byte, now named `gAskDisplayMode`, at `803DE2F8` /
`803DE4B8`. Decoding each retail r13 base and scanning the executable finds
exactly one `stb` and one `lbz` for this storage, both in `init`; there are no
word loads/stores to support the old pointer declaration. The three trailing
alignment bytes are not part of the flag. The unused progressive-mode byte and
yes/no X coordinates are omitted from PAL, matching its small-data layout.

`mmInit` correspondingly allocates 0x6EC save-buffer bytes in PAL, rather than
EN/JP's 0x6ED bytes. It does not store a pointer to an extra byte at +0x6EC.
The other versions preserve their existing allocation and pointer.

## Remaining BSS problem

The tentative request definition had been deferred past the later BSS objects
by its earlier `extern`. Defining it before first use restores its correct first
position. The remaining four bytes between it and the player-trail buffer have
no recovered ownership or alignment contract:

| EN symbol | Retail address | Reconstructed source-link address |
| --- | --- | --- |
| gGameLoopAssetReq | `8033BF88` | `8033BF88` |
| gGameLoopPlayerTrailBuffer | `8033BFB8` | `8033BFB4` |
| gGameLoopRenderModeCopy | `8033C378` | `8033C374` |
| lbl_8033C3B8 | `8033C3B8` | `8033C3B4` |

The old object boundary supplied four bytes of linker alignment and concealed
this unresolved layout. No dummy global, enlarged request struct, alignment
override, or new artificial split was introduced to restore that accident.
An independent merged-source link confirms the addresses above and fails the
retail hash as expected. Objdiff's 100% data measure does **not** establish correct
BSS symbol addresses. The merged TU stays NonMatching in every version.

## Validation and progress

- PAL `init` is now exact: 1,304 bytes in each release, up from 83.48%.
- PAL `mmInit` is now exact: 308 bytes in each release, up from 97.39%.
  Both complete 32-function memory-management units are now verified source links
  and are included in their regional progress manifests.
- Final merged game-loop fuzzy scores are 99.99689% in EN, EN rev1 and JP
  (40/41 exact functions), and 99.91901% in both PAL releases (39/41 exact).
  PAL's display-mode prompt retains its previously measured 99.380165% score.
- The two EN/JP reset-function match regressions are included in those counts.
  Removing the artificial completed fragments also reduces completed-unit counts;
  this is structural recovery, not a claim that the whole game-loop TU is done.
- All five versions pass `ninja all_source`, independent all-retail links,
  memory-management-only source links, and native strict retail checksums.
  Every input DOL was checked against its configured SHA-1.
- Every other source object is byte-identical across all five builds. The memory
  manager objects are also byte-identical in EN, EN rev1 and JP. Retired fragment
  objects are absent from the generated link/build configuration.
