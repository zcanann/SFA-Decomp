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
