# Regional source-link retention

PAL v1.0 now reproduces its verified original DOL with all 918 units in
`config/GSAP01/matching_units.txt` substituted together. The remaining units and
automatic gaps still use retail objects. Both the all-retail control and the
combined source link have SHA1 `c5bb4a7fd3c4aff48c40e282d4d54795c37155f0`.
This validates the existing manifest together; it adds no progress claims.

## Retained source definitions

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
- JP (952 units) links but loses 480 text bytes and 216 data bytes, shifting
  later sections. Its combined manifest has not been certified.
- PAL rev1 (913 units) initially preserved all section addresses and sizes but
  differed in one pointer store. The subsequent
  [path-search identity repair](pathsearch_pointer_identity.md) makes its
  entire manifest reproduce retail too.

Reproduce a manifest check with `tools/verify_source_link.py VERSION`, passing
each non-comment source unit from that version's `matching_units.txt` after
configuring the version and building `all_source`. Secondary versions still
use ordinary configuration; the native `--matching` checksum target remains EN.
