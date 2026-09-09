# Player regional data identities

Six player-owned small-data definitions now have shared semantic names across
all five versions. Their original EN-address names caused two source-link
collisions with engine DLL 53 in EN rev1 and two with `GXAttr` in JP.
The unrelated regional strings and SDK data at those numeric addresses remain
intact.

Three complete functions have unique normalized correspondences in every
verified original: `playerState27`, `playerUpdateFallingMotion`, and
`playerStateOnCloudRunner`. Their six r13-relative loads or array-base
instructions independently establish the destinations below. All initialized
bytes agree with EN, and every destination lies within the existing player
small-data split at the same width as its source definition.

| Name (prefix `gPlayer`) | Bytes | EN | EN rev1 | JP | PAL v1.0 | PAL rev1 |
| --- | ---: | --- | --- | --- | --- | --- |
| `FallAnimSpeed` | 4 | `803DC684` | `803DD2EC` | `803DC7A4` | `803DDE84` | `803DE044` |
| `HitReactionMoves` | 8 | `803DC688` | `803DD2F0` | `803DC7A8` | `803DDE88` | `803DE048` |
| `HitReactionMoveSpeeds` | 8 | `803DC690` | `803DD2F8` | `803DC7B0` | `803DDE90` | `803DE050` |
| `CloudRunnerAimZResponse` | 4 | `803DC6D4` | `803DD33C` | `803DC7F4` | `803DDED4` | `803DE094` |
| `CloudRunnerAimXResponse` | 4 | `803DC6D8` | `803DD340` | `803DC7F8` | `803DDED8` | `803DE098` |
| `CloudRunnerTurnScale` | 4 | `803DC6DC` | `803DD344` | `803DC7FC` | `803DDEDC` | `803DE09C` |

The falling-motion function sets its target animation speed to 1. The
hit-reaction state clamps its variant to 1 or 2 and selects moves 210 or 212
with the corresponding speed. Preserve the speed literal `0.030000001f`
(`3CF5C290`); ordinary `0.03f` is the neighboring float `3CF5C28F`, which is
used by the three CloudRunner controls. The latter interpolate the existing
Z/X aim inputs and scale the turn increment after its dead zone.

Only identities change: source declarations, definition order, types, values,
and ownership remain in place. Each player's allocated object bytes, section
layout, relocations and symbol properties are unchanged except for the six
names. Other source objects are unchanged apart from the separately recovered
[SDK matrix source](sdk_mtx44_recovery.md).

All five source builds pass, and both edited units retain exact direct objdiff
comparisons. In every version, substituting the two source units together
reproduces the original DOL. EN passes its strict checksum. The combined
manifests also reproduce EN rev1 (923 source units), PAL v1.0 (918) and PAL
rev1 (913). Remaining units and automatic gaps still use retail objects;
these validations do not claim a complete regional source build or add progress
counts.
