# Slot 691 vortex layers

The generated source identity remains `dlls/objects/691/691.c`. The existing
Vortex namespace describes the visual family; secondary object names do not
authorize renaming this numbered source path.

The nine EN functions occupy `80237808..802383E0`. Data consists of the
48-byte scale table at `8032BE20`, followed by the terminal 56-byte descriptor
at `8032BE50`. Seven small tables occupy `803DC3E8..803DC418`, and the complete
constant pool occupies `803E73D0..803E7408`. No boundary or alignment changes
are required. The two eight-byte speed symbols have three indexed signed
halfwords and two unaccessed bytes; those tails remain opaque.

`Vortex_getExtraSize` returns 40 bytes. The state contains an activation fade,
particle timer, three layer opacity multipliers, three layer size multipliers,
three angles, and the active bit at the high bit of byte `0x26`. The fade
controls geometry, vertical displacement and particle scale as well as opacity.
The WndLift variants initialize and render only two layers; other variants use
three. The original assignment of `mainGetBit` to the one-bit field is retained:
it takes the result's low bit rather than testing whether the whole result is
nonzero.

The placement reader exposes these signed halfwords:

| Offset | Role |
| --- | --- |
| `0x1A` | WndLift size multiplier in units of `1/16384` |
| `0x1C` | WndLift reverse texture-scroll selector |
| `0x1E` | WndLift scroll-reversal game bit, or default-init / SkyVort-update activation-suppression bit |
| `0x20` | Activation game bit; `-1` leaves the active state clear |

Canonical union views at `0x1E` distinguish the two behaviors. Initialization
uses suppression in its default branch; subsequent updates apply it only to
SkyVortC (`0x29A`) and SkyVortS (`0x829`). This asymmetry is preserved.
No EN producer establishes a full serialized placement extent, so the type
is a reader prefix through `0x21`. EN rev1 and JP each contain 46 records, all
36 bytes: 24 WndLiftS, 16 WndLiftC, four SkyVortC, one DIM_PitVort and one
SkyVortS. These are secondary width and family evidence only.

The render callback at `80237848` preserves several unusual retail behaviors.
Wind lifts use a particle timer; the default branch emits on each eligible
render. The HUD counter pauses render-time animation and particle emission,
while update-time activation fading still uses `timeDelta`. The renderer
restores root scale, base alpha, `rotX` and local Y, but leaves render alpha,
model buffer flag changes, and the wind-lift `rotZ` assignment in place.
DIM_PitVort and default branches check the texture pointer before scrolling,
then read its offset outside that guard; the DIM_PitVort read is at `80237C60`.
No null guard or additional state restoration has been invented.

The nine owner functions and three inspected shared helpers have equal
normalized instruction signatures across the four verified EN, EN rev1, JP and
PAL rev1 DOLs. All 96 table bytes and 56 constant-pool bytes are identical.
Recovery preserves complete object bytes, including symbol order and
relocations. Four-version source builds and objdiff reports, followed by the
strict EN checksum, gate the change. This improves the recovered source of an
already exact unit without claiming a new match-percentage gain.
