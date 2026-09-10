# SRAM language and video-mode accessors

`dolphin/os/OSRtc.c` now matches completely in all five configured versions.
EN rev1 was missing the 108-byte `OSGetLanguage` function. PAL v1.0 and PAL rev1
also use the RGB60 accessors in place of the progressive-mode accessors.

The existing SDK compiler profile and the single TU are unchanged. Source
definitions follow retail order:

| Versions | After the sound-mode accessors |
| --- | --- |
| EN v1.0 / JP | Progressive getter/setter, then wireless IDs. |
| EN rev1 | Progressive getter/setter, language getter, then wireless IDs. |
| PAL v1.0 / PAL rev1 | Language getter, RGB60 getter/setter, then wireless IDs. |

## Evidence and implementation

`OSGetLanguage` locks SRAM, reads `OSSram.language` at byte `0x12`, and unlocks
without committing. Its implementation is corroborated by Mario Party 4's
`src/dolphin/os/OSRtc.c`. The current TU's existing lock wrapper supplies the
retail inlining behavior.

The PAL RGB60 accessors use bit 6 of `OSSram.ntd` at byte `0x11`. The getter
normalizes the bit to zero or one. The setter masks its input to one bit,
compares it with the stored bit, and unlocks without committing if unchanged.
Otherwise it preserves the other `ntd` bits and commits the update. This is
the same field and operation found in the Wind Waker and Pikmin 2 references.
The progressive-mode accessors instead use bit 7 of `OSSram.flags` at byte
`0x13`; they remain in the non-PAL builds.

The RGB60 setter keeps the currently stored masked flag in a named local.
This emits retail's 32-byte stack frame. Inlining that expression into the
comparison instead produces a 24-byte frame, leaving seven stack operands
different despite otherwise identical instructions. No unused stack filler
or compiler override is needed.

| Function | EN rev1 | PAL v1.0 | PAL rev1 | Size |
| --- | --- | --- | --- | --- |
| `OSGetLanguage` | `80245FF4` | `80245FF0` | `80246128` | 108 bytes |
| `OSGetEuRgb60Mode` | — | `8024605C` | `80246194` | 112 bytes |
| `OSSetEuRgb60Mode` | — | `802460CC` | `80246204` | 164 bytes |

The EN rev1 language getter's generic symbol is renamed to the existing SDK
API. PAL's names were established while recovering the game-loop and title-menu
callers. The new source now supplies those entry points.

## Validation

All five original DOLs were verified against their configured hashes. Objdiff
reports 100% code and data for the full unit: 16 functions / 2,896 code bytes in
EN v1.0 and JP, and 17 functions / 3,004 code bytes in the later versions. Every
version has 88 matching data bytes. EN rev1 gains one exact function; each PAL
version gains three. Their matching manifests now include the unit.

All five `all_source` builds and native strict checksum targets pass. Independent
all-retail links and links replacing only the SRAM source object reproduce each
original DOL exactly. EN v1.0 and JP objects remain byte-identical; every other
source object is unchanged across all five versions. The SRAM unit's allocated
non-code bytes, symbol positions, and non-code relocations are unchanged.
