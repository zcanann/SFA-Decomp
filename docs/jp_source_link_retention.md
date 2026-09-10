# JP retention and native regional checksum builds

All five versions support `python configure.py -v VERSION --matching` followed
by `ninja`. The default matching build now requires the original-DOL checksum
even when its final target is a progress report. EN v1.0 remains the default
version. Ordinary non-matching regional progress builds retain their existing
behavior.

These builds combine completed source units with retail objects for unfinished
units and automatic gaps. They do not imply complete source recovery. The four
secondary manifests reproduce their verified originals. Native matching builds
also include two explicitly verified library units whose constructor or
exception entries are left unscored by objdiff:

| Version | Manifest units | Native completed units | Original SHA1 |
| --- | ---: | ---: | --- |
| EN rev1 | 923 | 925 | `8bde4669c75260cc058b8b44ef36bacff3a67d20` |
| JP | 952 | 954 | `a0646def31229c051f5143e6551840e6560b0556` |
| PAL v1.0 | 918 | 920 | `c5bb4a7fd3c4aff48c40e282d4d54795c37155f0` |
| PAL rev1 | 913 | 915 | `c1a6ccdc61c7e719e20ea7cc59c8de09fd183e66` |

PAL v1.0 now joins the existing completion exceptions for
[MSL float trigonometry](msl_trig_initialization.md) and
[MusyX volume calculation](musyx_volume_completion.md). Its replacement DOL
passes the configured hash, and substituting those source units together
reproduces it exactly. This adds two completed PAL units covering 2,948 code
bytes and 672 data bytes without changing the conservative manifest or forcing
names onto compiler-generated records.

## JP's remaining retention defects

The combined JP source link initially lost 480 text bytes and 216 data bytes.
The first displacement followed the uncalled 448-byte `cardShowMessage`.
Its disappearance also discarded `cardSetStatusNeedInit` (12 bytes),
`saveGameGetStatus` (eight bytes), and its 48-byte jump table. Later text
alignment accounted for the remaining 12-byte displacement. The other 168
missing data bytes were `gMemoryCardBannerAssetNames`.

Retaining the dialog and banner block restored every section address and size,
but 17,532 bytes still differed. Most were consequences of two missing
four-byte audio BSS objects, `sAudioUnused0` and `sAudioUnused1`: the resulting
eight-byte displacement propagated through thousands of r13 references despite
the final section size being preserved by alignment. Two initialized words,
`lbl_803DB1EC` in audio and `lbl_803DBA00` in DLL 53, also disappeared before
referenced strings or texture IDs. Retaining those four existing definitions
makes the entire 952-unit JP manifest exact.

Every retained definition already had an EN retention rule. The four secondary
configs now also retain `cardShowMessage` and the three audio words. The dialog
has a unique whole-function normalized correspondence in each original; audio's
source data sections compare exactly in all five versions. Its initialized
word and two BSS slots keep stable offsets of 4, 68 and 116 in their respective
source sections, within the corresponding retail TU spans.

JP additionally inherits the banner and DLL 53 word rules. Both owning TUs
compare exactly in EN and JP. The other versions have differences in those
TUs, so these two rules were not copied indiscriminately. In particular, EN
rev1 reorders the banner strings; PAL omits `STARFOX ADVENTURES` and includes
different neighboring data in the currently named span. See the existing
[retail string census](rom_census/README.md).

## Validation

All five native matching builds pass `all_source` and the strict default
checksum target. Every compiled source object remains byte-identical: this
change affects retention and build gating, not C/C++, layouts or compiler
profiles. For each secondary version, the native completed-source set equals
its manifest plus the two documented library exceptions. The native DOLs equal
the verified originals byte-for-byte, and
the existing source-link verifier independently validates the full JP manifest.
No manifest entries, expected hashes or checksum checks are changed.
