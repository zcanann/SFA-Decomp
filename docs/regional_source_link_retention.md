# Regional source-link retention

PAL v1.0 now reproduces its verified original DOL with all 918 units in
`config/GSAP01/matching_units.txt` substituted together. The remaining units and
automatic gaps still use retail objects. Both the all-retail control and the
combined source link have SHA1 `c5bb4a7fd3c4aff48c40e282d4d54795c37155f0`.
This validates the existing manifest together; it adds no progress claims.

## Retained source definitions

The sky color-table retention below describes the historical link repair.
[Sky lighting curve recovery](sky_lighting_record.md) subsequently identifies
those actively read samples as three referenced arrays and removes their
separate retention rule. The complete sky TU matches all five versions;
the trailing small-data word still needs retention.

The previous combined PAL link resolved its symbols but lost unreferenced
functions and data. Some apparently unreferenced objects are accessed through
offsets from neighboring symbols. EN already retains these definitions. The
same rules now apply to the four secondary versions after checking each DOL.

| Source unit | Retained definitions | Bytes before alignment |
| --- | ---: | ---: |
| `dlls/engine/5/5.c` | Sky color table and unused small-data word | 64 |
| `dlls/objects/429_SH_thorntai/SHthorntail.c` | 13 state and dialogue tables | 1,242 |
| `dlls/objects/597/597.c` | SnowBike gamebit pairs | 12 |
| `main/audio_stream.c` | Two looped-object sound arrays | 768 |
| `main/boot_logo.c` | 12 GPU diagnostic strings | 423 |
| `main/objlib.c` | `gObjLibZero` | 4 |
| `main/shader_dolphin.c` | Warped-ring axes and indirect matrix | 72 |
| `main/thp/THPRead.c` | Three message arrays | 120 |
| `main/thp/THPVideoDecode.c` | Decoder thread stack | 4,096 |
| `track/intersect.c` | `surfaceSfxGetRecord` and unused small-data word | 124 |

These are 39 definitions totaling 6,925 bytes: 120 text, 1,737 data, 72 rodata,
4,984 BSS, eight small BSS and four small constants. PAL v1.0 gains all 39 rules;
the other secondary targets already retained the two shader tables and gain 37.
No source definitions, padding, section ownership or compiler profiles change.

For every version, all ten units compare exactly with completion annotations
disabled. Each retained symbol's source section, offset and size are stable and
fit the target TU span; initialized retained data matches the original bytes.
Combined source links establish the final addresses, alignment and relocations.

The first 38 rules restored every PAL section address and size, leaving 34
differing words (53 bytes). Retaining `gObjLibZero` fixes 18 loads and six pool
words in `objlib`; alignment had concealed that pool's lost leading zero.
The remaining ten loads require the constant identities below.

## Shared staff hit-reaction constants

Landed Arwing's hit-reaction helper operates on the staff-activated placement
contract and is reused by staff-activated mechanisms. Four external floats now
have shared semantic names in both consumers and all five symbol configs.
Four uniquely corresponding complete functions provide 11 retail `lfs` loads
per version. Their regional r2 bases independently establish every destination;
all references agree and all four-byte values equal EN. The generic render
wrapper has multiple identical candidates and was excluded from this evidence.

| Name (prefix `gStaffReaction`) | Value | EN | EN rev1 | JP | PAL v1.0 | PAL rev1 |
| --- | ---: | --- | --- | --- | --- | --- |
| `DebrisYOffset` | 2 | `803E3BB8` | `803E4850` | `803E3CD8` | `803E53D0` | `803E5598` |
| `One` | 1 | `803E3BBC` | `803E4854` | `803E3CDC` | `803E53D4` | `803E559C` |
| `SearchDistance` | 100 | `803E3BC0` | `803E4858` | `803E3CE0` | `803E53D8` | `803E55A0` |
| `StepScale` | 0.01 | `803E3BC4` | `803E485C` | `803E3CE4` | `803E53DC` | `803E55A4` |

`StepScale` also scales debris velocity randomization. Three old EN-address
names resolved to unrelated PAL locations; the fourth was already correct but
is renamed consistently. Unrelated regional numeric labels remain intact, and
the constants remain in their existing automatic pool. Source object bytes,
section layout, relocation records and symbol properties are unchanged except
for the external names. All other source objects remain byte-identical.

## Validation and remaining regional work

All five versions pass `all_source`. In each version, both the all-retail link
and a link substituting these twelve source units together reproduce the
verified original DOL. The two edited object TUs retain all 24 functions,
7,924 code bytes and 688 data bytes exactly under direct objdiff comparison.
Overall progress measures remain unchanged. EN also passes its strict checksum.

The PAL v1.0 test additionally substitutes its entire 918-unit manifest as
described above. Other full-manifest probes remain diagnostic:

- EN rev1 (923 units) initially failed on duplicate matrix and player names.
  [Recovering the SDK matrix source](sdk_mtx44_recovery.md) and
  [player data identities](player_regional_data_identities.md) makes its
  entire manifest reproduce retail too.
- JP (952 units) initially lost text, data and internal small-data slots.
  The subsequent [JP retention repair](jp_source_link_retention.md) makes its
  entire manifest reproduce retail too.
- PAL rev1 (913 units) initially preserved all section addresses and sizes but
  differed in one pointer store. The subsequent
  [path-search identity repair](pathsearch_pointer_identity.md) makes its
  entire manifest reproduce retail too.

Reproduce a manifest check with `tools/verify_source_link.py VERSION`, passing
each non-comment source unit from that version's `matching_units.txt` after
configuring the version and building `all_source`. All five versions now also
support the [native `--matching` checksum build](jp_source_link_retention.md).

## Restoration, 2026-09-26

All five DOLs matched again after four defects. EN v1.0 was the only one still
byte-exact when this started; JP, PAL v1.0, EN v1.1 and PAL v1.1 had drifted by
192, 64, 224 and 320 bytes as newer source landed. Each version is back to its
`build.sha1`.

**The instrument.** Section sizes are a poor screen because a retail carve
legitimately runs past the object it came from -- the linker's own inter-unit
padding is inside the carve -- so most size deltas are benign and EN has dozens
of them. What localises a drift is the linked ELF: compare every retail symbol
address against `nm build/<V>/main.elf`, per section, and report the first
divergence. `.text` all-exact with a data section shifted names the section;
the first shifted symbol names the unit; that unit's carve-versus-object delta
says whether bytes were lost inside it. Anonymous `@N` pool labels must be
excluded -- they are per-TU and collide across units, producing false origins.

**Four causes, in the order they were found.**

1. *A carve that runs past the object's natural end.* JP and EN v1.1 ended
   `pi_dolphin`'s `.data` eight bytes beyond what the source object emits, while
   EN, PAL and PAL v1.1 ended it exactly there. dtk turns the surplus into a
   `gap_*` filler inside the retail object, which a source link simply does not
   have. Cross-version disagreement about the same boundary is the tell.
2. *Dead-stripping.* A unit can be 100% in objdiff and still lose bytes: an
   unreferenced data object is dropped by the linker and everything after it in
   that section moves. Diff each source object's defined data symbols against
   the linked ELF to get the exact set, then list them in `force_active`. JP and
   PAL v1.1 were each missing thirty-odd, the largest being `shader.c`'s
   196-byte `sShaderObjLoadMessages`.
3. *Two symbols that must NOT be retained.* `GXNtsc480Prog` (60 bytes) is
   genuinely absent from retail PAL. `__OSFpscrEnableBits` is subtler and was the
   last defect in all four DOLs: it is dead-stripped on EN too, and the four
   zero bytes the linker inserts as alignment padding in its place reproduce
   retail exactly. Retaining it moved the pooled newline literal four bytes and
   cost two `.text` bytes as well. Over-retention is as damaging as
   under-retention, and only the DOL distinguishes them.
4. *Function emission order.* MWCC lays a translation unit's functions out in
   **reverse source order** -- measured on `dlls/engine/0/0.c`, 117 of 117
   adjacent pairs inverted. So a function must be declared *after* its neighbour
   to be emitted *before* it. `gameUiDrawNpcDialogueText`, which only PAL and the
   v1.1 builds compile, sat 452 bytes out of place and shifted the whole `.text`
   tail of three DOLs until it was moved below `gameUiUpdateNpcDialogue`.

**Two compiler facts worth keeping.** MWCC always emits `.sdata` with 8-byte
alignment (`-align` does not change it, and a translation unit holding nothing
but one `u32` still reports `2**3`), so a source object can never be placed at a
4-mod-8 `.sdata` address -- if retail wants one there, the bytes belong to the
preceding unit or to alignment padding. And a pooled two-byte string literal is
padded to four, so a reconstructed trailing gap should declare only the bytes
the compiler does not already emit.
