# Regional call identities and OSReboot's false function boundary

OSReboot now matches completely in EN rev1, JP and PAL rev1: four functions,
536 code bytes and 48 data bytes per version. Its shared source already matched
EN; the regional configs had split one assembly helper at an internal `blr` and
left the remaining helper names unresolved.

## OSReboot function layout

| Function | Size | EN | EN rev1 | JP | PAL rev1 |
| --- | ---: | --- | --- | --- | --- |
| `Run` | 64 | `80244554` | `80244C4C` | `80244644` | `80244E94` |
| `Callback` | 12 | `80244594` | `80244C8C` | `80244684` | `80244ED4` |
| `__OSReboot` | 448 | `802445A0` | `80244C98` | `80244690` | `80244EE0` |
| `OSSetSaveRegion` | 12 | `80244760` | `80244E58` | `80244850` | `802450A0` |

The regional configs ended `Run` after 44 bytes and treated its final 20 bytes as
a second function. Those bytes restore LR, r31 and the stack frame created by
the first block, then return. They correspond to the existing assembly helper's
`frfree; blr` after its transfer through LR. The complete 64-byte helper agrees
with the EN retail instruction sequence; its normalized surrounding TU also
agrees. The source file boundary and section ownership do not change.

`Run` and `Callback` retain local linkage. `OSSetSaveRegion` retains public
linkage. The four-function source object substitutes into each secondary retail
link without changing any DOL byte.

## Getter identities from direct callers

The new read-only `call_symbol_audit.py` uses only globally unique normalized
caller bodies, without name-based fallback. A candidate requires calls from at
least two distinct functions, a single target destination, no other observed
source callee sharing that target, a known target function start, and an equal
normalized callee body. Unknown/interior destinations remain in conflict
evidence. Multiple calls in one caller do not satisfy independence.

This identified `OSSetSaveRegion` in EN rev1 and JP, leading to the complete
OSReboot review, and these PAL getters:

| Function | PAL address | Code bytes | Observed calls |
| --- | --- | ---: | ---: |
| `getCurGameText` | `80019C28` | 8 | 9 |
| `getSaveFileStruct` | `800E8378` | 12 | 4 |
| `getLastSavedGameTexts` | `800E849C` | 16 | 6 |

Their compiled instructions, after resolving every relocation against the PAL
configuration and retail r13 base, equal retail exactly. The globals are
`curGameTextDir` at `803DE39C`, `saveData` at `803A4B24`, and `gSaveGameData` at
`803A4C08`; the last getter adds `0x558`. Their containing game-text and save
units remain incomplete. These names do not claim a full source link for those
larger units.

## Validation

- Matched code increases by 88 bytes in EN rev1, 88 in JP and 124 in PAL rev1:
  300 bytes total. Each gains a complete OSReboot unit. PAL additionally gains
  the three exact getters above.
- The spurious epilogue symbol is removed, so each secondary report has one
  fewer total function; no code bytes leave the progress denominator.
- All 988 source objects remain byte-identical in each secondary version.
  All-retail and OSReboot source-substitution links reproduce all three verified
  secondary DOLs. EN source and strict retail checksum builds also pass.
- The 88 targeted call, SDA, version-projection, jump-table and pool-audit tests
  pass. Regressions cover conflicting/shared targets, missing boundaries,
  changed callees, duplicate caller shapes and relative/absolute call decoding.

```sh
python3 tools/orig/call_symbol_audit.py GSAP01_rev1 --all --symbol getCurGameText
python3 tools/verify_source_link.py GSAP01_rev1 dolphin/os/OSReboot.c
```

## PAL v1.0 follow-through (2026-09-09)

The verified PAL v1.0 DOL has the same four-function reboot implementation:
`Run` at `80244D5C` (64 bytes), `Callback` at `80244D9C` (12),
`__OSReboot` at `80244DA8` (448), and `OSSetSaveRegion` at `80244F68`
(12). Its false `80244D88` epilogue symbol is removed. The complete normalized
bodies agree with EN, including the stack frame and restoration in `Run`.

Four PAL v1.0 getter names also follow independently matched callers. Their
compiled bytes, with every relocation resolved against the retail configuration
and startup r13 base `803E4980`, reproduce the retail functions exactly:

| Function | PAL v1.0 address | Code bytes | Global / return value |
| --- | --- | ---: | --- |
| `getCurGameText` | `80019C28` | 8 | load `curGameTextDir` at `803DE1DC` |
| `getSaveFileStruct` | `800E8380` | 12 | `saveData` at `803A4964` |
| `getLastSavedGameTexts` | `800E84A4` | 16 | `gSaveGameData` (`803A4A48`) + `558` |
| `saveGameGetEnvState` | `800E8958` | 16 | `gSaveGameData` + `6A8` |

The projector additionally names the intervening `loadSaveSettings` at
`800E838C`. Its complete 280-byte normalized body uniquely matches PAL rev1;
its calls set widescreen, subtitles, rumble, sound mode, volumes and language.
It is larger than EN's 256-byte implementation and receives no exact-match
claim. The getter-containing game units remain incomplete.

### MetroTRK trap boundary

PAL v1.0 had attributed the first eight-byte file trap to `targimpl.c`. The
four identical `twui r0, 0; blr` entries occupy `8028D1A0..8028D1C0`, matching
the complete `targsupp.s` block in the other four verified versions. The
console writer calls the first slot (`TRKAccessFile`), and console close calls
the third (`TRKCloseFile`), just as in EN. The unused second and fourth slots
retain the shared source's ordered `TRKOpenFile` and `TRKPositionFile` names;
their identical bodies alone cannot distinguish those two identities.

EN leaves twelve alignment bytes after `TRKValidMemory32`, whereas PAL v1.0
leaves four. The old projection carried the longer tail into PAL's first trap.
With the call-backed first-slot name in place, the existing projector recovers
the correct `8028D1A0` boundary for both neighboring units. No compiler profile,
source function, or data ownership changes. `targimpl` now contains its proper
30 functions and matches completely.

Together these corrections add 148 matched code bytes and two exact source
units in PAL v1.0. No previously exact unit regresses, code/data denominators
remain unchanged, and the removed false epilogue reduces the function
denominator by one. All 988 existing compiled source objects are unchanged.
The all-retail link and a link substituting `OSReboot.c`, `targimpl.c` and
`targsupp.s` both reproduce PAL v1.0's verified original DOL exactly.

PAL v1.0 and EN `all_source` builds pass. EN also passes the strict retail
checksum, with unchanged progress measures and source object bytes. The PAL
manifest now records 916 exact source units.

## Three trailing-return boundaries (2026-09-09)

EN rev1, JP, PAL v1.0 and PAL rev1 each split an unreachable trailing `blr`
from three otherwise complete functions. Their full normalized bodies each
have one unique correspondence with EN. The preceding instruction branches
back inside the same function; no direct branch, paired HI/LO materialization,
or aligned non-executable DOL word points to any of the twelve false entries.
The repairs preserve the containing TUs, section ownership and total code bytes.

| Function | Bytes | EN | EN rev1 | JP | PAL v1.0 | PAL rev1 |
| --- | ---: | --- | --- | --- | --- | --- |
| `Obj_UnregisterEffectBox` | 264 | `8002B758` | `8002B830` | `8002B758` | `8002B8CC` | `8002B8CC` |
| `streamInit` | 204 | `80272EA4` | `80273608` | `80272F94` | `802736DC` | `80273814` |
| `aramInitStreamBuffers` | 200 | `80284570` | `80284CD4` | `80284660` | `80284DA8` | `80284EE0` |

The uniquely matched `sndInit` and `aramInit` callers independently establish
the two MusyX identities. `Obj_UnregisterEffectBox` removes an object from the
EffectBox array and decrements its count. Resolving all seven relocations in
its compiled body reproduces all 264 retail bytes in each secondary version:

| Version | `gEffectBoxObjects` | `gEffectBoxObjectCount` | r13 base |
| --- | --- | --- | --- |
| EN rev1 | `80341508` | `803DD7F4` | `803E3E40` |
| JP | `803409C8` | `803DCC94` | `803E3300` |
| PAL v1.0 | `80342048` | `803DE36C` | `803E4980` |
| PAL rev1 | `80342208` | `803DE52C` | `803E4B40` |

The larger `main/object.c` remains incomplete. The exact EffectBox DLL source
also links against the recovered function destination in the substitution check.

### Retained MusyX storage

Substituting `aram_data.c` initially shortened `.bss` by 24 bytes and shifted
later sections. EN already force-retains its unreferenced `lbl_803D4868` source
symbol. Each secondary TU owns the same `0x418`-byte BSS span: the referenced
`0x400`-byte stream-buffer array followed by this opaque 24-byte block. Carrying
the existing retention rule into the secondary configs restores the retail
layout. The retained name is the shared source identifier, not a regional
absolute address. No source padding, symbol address or split was added.

| Version | Opaque BSS tail |
| --- | --- |
| EN | `803D4868..803D4880` |
| EN rev1 | `803D54C8..803D54E0` |
| JP | `803D4988..803D49A0` |
| PAL v1.0 | `803D6008..803D6020` |
| PAL rev1 | `803D61C8..803D61E0` |

### Validation and accounting

Each secondary gains 464 newly reported code bytes and one complete
`aram_data.c` unit. The three removed false entries reduce its function
count by three; total code and data denominators stay unchanged. No unit loses
matched code or data. The accompanying PAL GX mode-name recovery adds one
more complete unit and 240 data bytes, documented in
[regional GX recovery](regional_gx_jump_tables.md).

A direct objdiff comparison with `metadata.complete` disabled verifies all
668 bytes across the three repaired functions. Normal reports previously
credited `streamInit`'s 204 bytes from its completion annotation despite the
incorrect target boundary; those bytes are not counted again as new progress.
Use `tools/unitfuzzy.py` or an objdiff project with `metadata.complete: false`
to measure source correspondence independently of a manifest's assertion.

All five `all_source` builds pass, and every compiled source object remains
byte-identical. Each verified original DOL is reproduced both by an all-retail
link and by substituting these eight source units together: `GXInit.c`,
`GXFrameBuf.c`, `GXLight.c`, `GXTexture.c`, `synth_job_init.c`, `aram_init.c`,
`aram_data.c`, and `238_EffectBox/EffectBox.c`. EN also passes its strict retail
checksum. Compiler profiles and C sources are unchanged.
