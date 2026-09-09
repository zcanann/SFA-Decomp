# Arwing regional constant identities

The shared Arwing TU had 37 external float references named after EN addresses.
The complete PAL v1.0 manifest link reported 36 of those names as undefined;
the remaining roll-cooldown label happened to resolve there. All 37 now have
unit-owned names and independently verified destinations in all five versions.

## Retail evidence

Five complete functions have unique normalized correspondences in every verified
DOL: `arwarwing_initAttachments`, `arwarwing_resetFlightState`,
`arwarwing_render`, `arwarwing_hitDetect`, and `arwarwing_update`. Their 61
`lfs` instructions locate the 37 floats using the actual regional r2 bases.
All references to each float agree on its address, and all four bytes agree
with EN. The table records the recovered source names, not historical symbols.

| Name (prefix `gArwing`) | Value | EN | EN rev1 | JP | PAL v1.0 | PAL rev1 |
| --- | ---: | --- | --- | --- | --- | --- |
| `DeathSpinRate` | 1500 | `803E6F6C` | `803E7C04` | `803E708C` | `803E879C` | `803E8964` |
| `MaxLateralSpeed` | 13 | `803E6F70` | `803E7C08` | `803E7090` | `803E87A0` | `803E8968` |
| `LateralResponse` | 0.04 | `803E6F74` | `803E7C0C` | `803E7094` | `803E87A4` | `803E896C` |
| `MaxVerticalSpeed` | 9 | `803E6F78` | `803E7C10` | `803E7098` | `803E87A8` | `803E8970` |
| `VerticalResponse` | 0.05 | `803E6F7C` | `803E7C14` | `803E709C` | `803E87AC` | `803E8974` |
| `MaxForwardAccel` | 0.2 | `803E6F80` | `803E7C18` | `803E70A0` | `803E87B0` | `803E8978` |
| `MinForwardAccel` | -0.1 | `803E6F84` | `803E7C1C` | `803E70A4` | `803E87B4` | `803E897C` |
| `YawRange` | 7800 | `803E6F88` | `803E7C20` | `803E70A8` | `803E87B8` | `803E8980` |
| `PitchRange` | 7500 | `803E6F8C` | `803E7C24` | `803E70AC` | `803E87BC` | `803E8984` |
| `RollRange` | 8000 | `803E6F90` | `803E7C28` | `803E70B0` | `803E87C0` | `803E8988` |
| `RollGain` | 0.11 | `803E6F94` | `803E7C2C` | `803E70B4` | `803E87C4` | `803E898C` |
| `RollTrimRange` | 16383 | `803E6F98` | `803E7C30` | `803E70B8` | `803E87C8` | `803E8990` |
| `RollTrimGain` | 0.07 | `803E6F9C` | `803E7C34` | `803E70BC` | `803E87CC` | `803E8994` |
| `RollBlendThreshold` | 7000 | `803E6FA0` | `803E7C38` | `803E70C0` | `803E87D0` | `803E8998` |
| `BlendRate` | 0.01 | `803E6FA4` | `803E7C3C` | `803E70C4` | `803E87D4` | `803E899C` |
| `BarrelRollSpeed` | 3000 | `803E6FA8` | `803E7C40` | `803E70C8` | `803E87D8` | `803E89A0` |
| `BarrelRollDecelRange` | 1000 | `803E6FAC` | `803E7C44` | `803E70CC` | `803E87DC` | `803E89A4` |
| `RootMotionScale` | 0.75 | `803E6FB0` | `803E7C48` | `803E70D0` | `803E87E0` | `803E89A8` |
| `BarrelRollMaxSpeedScale` | 1.5 | `803E6FB4` | `803E7C4C` | `803E70D4` | `803E87E4` | `803E89AC` |
| `BarrelRollAccelScale` | 1.6 | `803E6FB8` | `803E7C50` | `803E70D8` | `803E87E8` | `803E89B0` |
| `LeftRollSpeedScale` | 2 | `803E6FBC` | `803E7C54` | `803E70DC` | `803E87EC` | `803E89B4` |
| `LightOffsetY` | -15 | `803E6FC4` | `803E7C5C` | `803E70E4` | `803E87F4` | `803E89BC` |
| `LightOffsetZ` | -70 | `803E6FC8` | `803E7C60` | `803E70E8` | `803E87F8` | `803E89C0` |
| `LightNearDistance` | 60 | `803E6FCC` | `803E7C64` | `803E70EC` | `803E87FC` | `803E89C4` |
| `LightFarDistance` | 110 | `803E6FD0` | `803E7C68` | `803E70F0` | `803E8800` | `803E89C8` |
| `LeftRollAccel` | 0.15 | `803E6FD4` | `803E7C6C` | `803E70F4` | `803E8804` | `803E89CC` |
| `NeutralForwardAccel` | 0.02 | `803E6FD8` | `803E7C70` | `803E70F8` | `803E8808` | `803E89D0` |
| `RollCooldown` | 180 | `803E6FDC` | `803E7C74` | `803E70FC` | `803E880C` | `803E89D4` |
| `RollEnergyMax` | 90 | `803E6FE0` | `803E7C78` | `803E7100` | `803E8810` | `803E89D8` |
| `BobRollAmplitude` | 600 | `803E6FE4` | `803E7C7C` | `803E7104` | `803E8814` | `803E89DC` |
| `BobYRate` | 350 | `803E6FE8` | `803E7C80` | `803E7108` | `803E8818` | `803E89E0` |
| `FlightHalfWidth` | 750 | `803E6FEC` | `803E7C84` | `803E710C` | `803E881C` | `803E89E4` |
| `FlightUpperHeight` | 300 | `803E6FF0` | `803E7C88` | `803E7110` | `803E8820` | `803E89E8` |
| `HitShakeAmplitude` | 768 | `803E6FF4` | `803E7C8C` | `803E7114` | `803E8824` | `803E89EC` |
| `AimCameraParameter` | 35 | `803E6FF8` | `803E7C90` | `803E7118` | `803E8828` | `803E89F0` |
| `ThrusterFadeInRate` | 4 | `803E6FFC` | `803E7C94` | `803E711C` | `803E882C` | `803E89F4` |
| `ThrusterAlphaMax` | 255 | `803E7000` | `803E7C98` | `803E7120` | `803E8830` | `803E89F8` |

The flight-physics and aim-snapshot consumers establish the rotation convention:
`rotX` becomes object yaw and `rotY` becomes pitch. Accordingly, the 7,800 range
is named `YawRange` and the 7,500 range `PitchRange`.

These pool names do not imply independently adjustable tuning variables.
Several values serve multiple fields: `LateralResponse` also supplies yaw gain
and right-roll acceleration; `VerticalResponse` supplies Y/Z acceleration and
pitch gain; `MaxVerticalSpeed` also initializes forward speed;
`MaxForwardAccel` supplies vertical bob amplitude; `LeftRollAccel` supplies
horizontal bob amplitude; `RollEnergyMax` also initializes projectile speed.
`BlendRate` serves roll and bob blending. The shared uses remain intact, and
local temporaries now describe their values instead of retaining address suffixes.
The final float passed to the aim-camera override remains conservatively named
`AimCameraParameter`; this change does not assign an unproven camera meaning.

## Literal reconstruction probe

Replacing all 37 external loads with exactly round-tripping float literals keeps
all 54 functions and 15,784 code bytes exact under direct objdiff comparison.
However, the source constant pool grows from 164 to 312 bytes with a different
order from retail. Its original 164-byte prefix stays exact; the newly emitted
floats begin with the light offsets instead of the retail death-spin value.
The separately named escort-search radius is also interspersed in the retail
pool. This establishes a pool-order reconstruction problem, not permission to
reorder confirmed functions or synthesize an unused constant-emitting helper.
The probe was restored byte-for-byte before the identity repair.

The retained change only renames the external identities and local temporaries.
It preserves the existing automatic pool, TU boundaries and compiler profile;
unrelated regional labels at the numeric EN addresses are untouched.

## Validation

Each version passes `all_source`. All-retail links and links substituting only
Arwing source reproduce the five verified original DOLs. Direct comparisons with
completion annotations disabled retain all 54 functions, 15,784 code bytes and
700 data bytes exactly. Overall progress scores remain unchanged. Allocated
object bytes, section layouts, relocation records and symbol properties are
identical except for the external names; all other source objects are unchanged.
EN passes its strict retail checksum.

The complete 918-unit PAL v1.0 manifest now links without undefined symbols,
but its DOL still differs from retail. The combined link shrinks `.text` by
112 bytes, `.rodata` by 72, `.data` by 1,800, and `.bss` by 4,960; `.sdata`,
`.sbss`, `.sdata2`, and `.sbss2` retain their sizes but move with earlier sections.
The first text displacement occurs at `waterFxUpdate`, immediately after the
120-byte `surfaceSfxGetRecord`. EN already explicitly retains that unreferenced
function, whereas PAL's force-active list omits it. Later text alignment reduces
the final text difference to 112 bytes. Other displacement transitions include
thread diagnostics, shadow/shader data, Thorntail tables, audio workspace and
video buffers. These are concrete retention/layout follow-ups, not a claim that
the full regional source link is recovered.
