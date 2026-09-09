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
