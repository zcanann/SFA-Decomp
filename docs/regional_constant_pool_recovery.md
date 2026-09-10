# Regional r2 constant identities

Several regional source units had exact normalized object scores but could not
link their external constants, or linked an EN address label to unrelated local
storage. The initialized small-data projector now handles `.sdata2` using the
retail r2 base, independently of the existing r13 `.sdata` / `.sbss` analysis.

## Evidence and limits

An imported symbol requires a unique operand destination in independently paired
retail functions, identical initialization bytes, and consistent offsets for
every observed interior reference. A whole section boundary additionally requires
the entire source range to pass those checks. Repeated float values and matching
names alone do not establish identity. Unowned constants may regain their names
without claiming an unproven TU pool.

Functions that overwrite the selected GPR base are excluded. In particular,
`TRKRestoreExtended1Block` loads `gTRKCPUState` into r2 at EN `8028CC88` and
`8028CC8C`; its subsequent loads are CPU-state accesses. Treating them as SDA2
references falsely projected EN `803E675C` onto EN rev1 `803E73DC`, overlapping a
real cloud-race constant. Both the regional projector and retail pool audit now
reject that evidence. FPR2 writes remain distinct from GPR2 writes.

The projector also preserves an unrelated regional address label when an imported
EN label would collide with it. Replacing the old storage does not free its name
if that replacement retains the same name. The audit prefers regional names for
anonymous literals unused by source, avoiding false mismaps from numeric name
coincidences.

## Recovered configuration

| Version | Newly available semantic SDA2 names |
| --- | ---: |
| EN rev1 | 106 |
| JP | 59 |
| PAL rev1 | 109 |

These include camera-climb, HUD, MagicPlant, SpiritDoorL, EarthWalker, bouncy-crate,
push-block and Arwing constants. Address-based source names are also restored
where they do not collide. Each version retains its own verified address and
bytes; no common displacement is assumed.

The engine DLL 0 pool ends at EN rev1 `803E2E64` and PAL `803E3BAC`, four bytes
before the previous ends. Those four bytes remain alignment gaps. Matched code,
matched data and completed-unit counts do not change; the total-data denominator
decreases by four bytes in each of those versions. JP report measures are unchanged.

## Spirit Door Lock: a normalized match with the wrong constant

`SpiritDoorLock_init` tests the placement scale against zero. Its legacy source
identifier `lbl_803E4430` collided with unrelated regional storage. After restoring
the seven semantic tuning constants, the JP source substitution linked but differed
from retail by one instruction: `C002DE10` instead of `C002DF30`.

The source now calls that same external zero `gSpiritDoorLockZero`. Its unique
paired initialization function witnesses these addresses, each containing
`00000000`:

| Version | Zero address |
| --- | --- |
| EN | `803E4430` |
| EN rev1 | `803E50C8` |
| JP | `803E4550` |
| PAL rev1 | `803E5E10` |

Unrelated regional `lbl_803E4430` records remain untouched. The change preserves
the TU, declarations, compiler profile and source expression; only the external
symbol identity changes. All nine functions, 1,440 code bytes and 96 data bytes
retain exact objdiff scores.

## Validation

The all-retail link and the link substituting SpiritDoorL source reproduce each
verified original DOL. All four versions pass `all_source`; EN also passes the
strict retail checksum. Only the renamed SpiritDoorL source object changes in
each secondary version; all other 987 source objects remain byte-identical.
The recovered SDA2 symbols, split ranges and symbol mappings survive regeneration.
The 77 targeted SDA, pool-audit, version-projection and jump-table tests pass.
Clang-format makes no additional changes to the active TU or its canonical header.

This does not establish a full regional source link. Push-block still exposes
colliding legacy references (`lbl_803E6D68`), and Arwing retains similar cases.
Those names need evidence-backed source recovery; silently redirecting unrelated
regional labels would hide incorrect relocations. The camera-climb collision is
resolved below.

```sh
python3 tools/orig/sda_symbol_audit.py GSAJ01 --section sdata2
python3 tools/verify_source_link.py GSAJ01 dlls/objects/359_SpiritDoorL/SpiritDoorL.c
```

## Climbing camera zero (2026-09-09)

Linking all 916 PAL v1.0 manifest units together exposed unresolved external
references that their normalized object reports did not reject. One was the
climbing camera's `lbl_803E19A0`. That spelling names unrelated storage in the
other four regional configs, including a local eight-byte double in JP.

The camera uses this value when its height is already between the target-relative
minimum and maximum: no vertical correction is needed. Its source now names the
constant `gCamClimbZero`. A globally unique whole-function instruction signature
identifies `CameraModeClimb_update` independently in all five verified DOLs.
The same `lfs` instruction offset, decoded against each retail startup r2 base,
loads exactly four zero bytes at these addresses:

| Version | Retail load instruction | Constant address |
| --- | --- | --- |
| EN | `8010D4D4` | `803E19A0` |
| EN rev1 | `8010D770` | `803E2620` |
| JP | `8010D4F4` | `803E1AC0` |
| PAL v1.0 | `8010D8F0` | `803E31A8` |
| PAL rev1 | `8010D900` | `803E3368` |

Only those proven symbols are renamed. Unrelated regional `lbl_803E19A0`
records retain their identities and addresses. The constant remains in its
existing automatic pool; this change does not invent a source definition or
claim additional pool ownership.

All five versions pass `all_source`, and both the all-retail and camera-source
substitution links reproduce their verified original DOLs. EN also passes its
strict matching checksum. Every report measure is unchanged. The camera object
changes only the external symbol spelling: all allocated bytes, symbol layouts
and relocation records are identical. Every other source object is unchanged.

The combined PAL manifest link remains incomplete. Its linker also reports
unresolved GX render-mode records, `aramInitStreamBuffers`,
`Obj_UnregisterEffectBox`, and external constants in EarthWalker, bouncy-crate,
push-block and Arwing. These are concrete linkage follow-ups, not proof that
their reported instruction matches are false. Individual normalized matches
continue to require final-address verification before a complete regional source
link can be claimed.

## Push-block burst and sound constants (2026-09-09)

`WCPushBlock` used six EN address labels for shared float constants. Several
labels were undefined in secondary links; others resolved to unrelated regional
storage. They now have unit-owned names based on the existing consumers:

| Name (prefix `gWcPushBlock`) | Value | Observed use |
| --- | ---: | --- |
| `One` | 1 | render factor and minimum slide-sound volume |
| `BurstScale` | 2 | burst scale and vertical extent |
| `BurstHorizontalExtent` | 65 | burst X/Z extent |
| `Zero` | 0 | stationary velocity, zero Y movement and sound-speed clamp |
| `SlideSfxSpeedThreshold` | 0.25 | speed subtracted before computing sound volume |
| `SlideSfxVolumeScale` | 0.5 | scale passed to the object-volume setter |

The complete normalized `wcpushblock_update` body is globally unique in each
verified DOL. Its twelve loads independently locate these six floats using
each version's retail r2 base. Every observed load agrees on its destination,
and all four bytes agree with EN. The resulting addresses are:

| Constant | EN | EN rev1 | JP | PAL v1.0 | PAL rev1 |
| --- | --- | --- | --- | --- | --- |
| One | `803E6D54` | `803E79EC` | `803E6E74` | `803E8584` | `803E874C` |
| Burst scale | `803E6D5C` | `803E79F4` | `803E6E7C` | `803E858C` | `803E8754` |
| Horizontal extent | `803E6D60` | `803E79F8` | `803E6E80` | `803E8590` | `803E8758` |
| Zero | `803E6D64` | `803E79FC` | `803E6E84` | `803E8594` | `803E875C` |
| Sound speed threshold | `803E6D68` | `803E7A00` | `803E6E88` | `803E8598` | `803E8760` |
| Sound volume scale | `803E6D78` | `803E7A10` | `803E6E98` | `803E85A8` | `803E8770` |

Only the source references and the proven regional symbols are renamed.
Unrelated symbols at the numeric EN addresses remain intact. The constants
retain their current automatic-pool ownership and external declarations; this
repair does not establish a new pool definition or change TU boundaries.

All five all-retail links and push-block source-substitution links reproduce
their verified originals. All five source builds and EN's strict checksum pass.
The push-block object's allocated bytes, section layout, relocation records and
symbol entries are unchanged apart from the six external names; every other
source object is byte-identical. The unit retains nine exact functions, 3,520
code bytes and 100 data bytes. This is a linkage and identity repair, with no
additional match-score credit.

The earlier unresolved GX modes and function names were repaired in the
[regional boundary batch](regional_call_identity_recovery.md#three-trailing-return-boundaries-2026-09-09).
EarthWalker, bouncy-crate and Arwing remain follow-ups for the combined PAL
manifest link; the checks above substitute only the reviewed push-block TU.

## EarthWalker and bouncy-crate constants (2026-09-09)

The remaining Walled City render and launch references now use five stable
source identifiers in all five versions:

| Name | Value | Consumer |
| --- | ---: | --- |
| `gEarthWalkerRenderScale` | 1 | the render helper's scale argument |
| `gBouncyCrateZero` | 0 | inactive launch speed and post-bounce velocity reset |
| `gBouncyCrateMaxLaunchSpeed` | 2 | initial vertical speed near the trigger |
| `gBouncyCrateLaunchFalloffRange` | 300 | linear launch-speed falloff between distances 200 and 500 |
| `gBouncyCrateOne` | 1 | launch interpolation and the render helper argument |

EarthWalker's render wrapper is not globally unique: `cfguardian_render` has
the same normalized instruction shape. Its descriptor independently resolves
that ambiguity. The globally unique `earthwalker_init` and `earthwalker_update`
bodies identify one descriptor record in each retail DOL, and its render slot
selects the correct wrapper from the two candidates:

| Version | Descriptor | Render callback |
| --- | --- | --- |
| EN | `8032AED4` | `8022312C` |
| EN rev1 | `8032BB2C` | `8022377C` |
| JP | `8032AFF4` | `8022321C` |
| PAL v1.0 | `8032C6AC` | `8022388C` |
| PAL rev1 | `8032C86C` | `802239C4` |

Bouncy-crate's complete update body is globally unique in all five DOLs.
Its seven loads, plus the selected EarthWalker wrapper's load, establish these
addresses from actual retail r2 operands. Every float's four bytes agree with EN:

| Constant | EN | EN rev1 | JP | PAL v1.0 | PAL rev1 |
| --- | --- | --- | --- | --- | --- |
| EarthWalker render scale | `803E6CE0` | `803E7978` | `803E6E00` | `803E8510` | `803E86D8` |
| Crate zero | `803E6D24` | `803E79BC` | `803E6E44` | `803E8554` | `803E871C` |
| Crate maximum launch speed | `803E6D2C` | `803E79C4` | `803E6E4C` | `803E855C` | `803E8724` |
| Crate launch falloff range | `803E6D34` | `803E79CC` | `803E6E54` | `803E8564` | `803E872C` |
| Crate one | `803E6D38` | `803E79D0` | `803E6E58` | `803E8568` | `803E8730` |

The repair preserves declarations, TU boundaries and automatic-pool ownership.
Unrelated regional symbols whose numeric names collide with the old EN labels
remain untouched. No compiler profile or regional source conditional changes.

All five all-retail links and combined EarthWalker/bouncy-crate source links
reproduce the verified originals exactly. Direct objdiff comparisons with
completion annotations disabled retain 18 exact EarthWalker functions (3,348
code and 152 data bytes) and ten exact bouncy-crate functions (872 code and 64
data bytes). Overall match measures do not change; this resolves previously
missing or incorrect external identities behind the existing exact scores.
Only the five external names change in the two source objects: allocated bytes,
section layouts, relocation records and other symbol properties are identical.
Every other source object is unchanged. All five source builds and EN's strict
checksum pass. Arwing's external constants remain the next combined PAL-link
follow-up.

A fresh PAL v1.0 diagnostic substitutes all 918 manifest source units. Its
all-retail link remains exact; the source link now reports 36 distinct
undefined constants, all referenced by `ARWArwing.o`. The repaired GX, MusyX,
camera, push-block, EarthWalker and bouncy-crate references no longer appear
in that error list. Successful symbol resolution alone will still need a final
DOL comparison before the full manifest link can be considered exact.

## Arwing follow-through

[The Arwing audit](arwing_constant_recovery.md) resolves all 37 legacy float
identities across the five versions and verifies each Arwing source link.
The complete PAL manifest now resolves all symbols, exposing retained-code and
data-layout differences for the next recovery pass. It still does not reproduce
the full retail DOL.
