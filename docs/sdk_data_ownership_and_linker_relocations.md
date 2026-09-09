# SDK data ownership and regional linker symbols

The verified PAL v1.0 DOL exposes the same SDK layout issues as EN rev1 and
PAL rev1. The shared source fixes require no regional conditionals or compiler
profile changes.

## DSP boot program belongs to OSAudioSystem

`DSPInitCode` is a 128-byte program used only by `__OSInitAudioSystem`, which
copies it into the aligned work buffer at `0x81000000` before DMA. It follows
OS.c's final diagnostic string and precedes OSCache.c's diagnostic pool in
retail data. OSAudioSystem owns the intervening program; OSAlarm, OSAlloc and
OSArena own no intervening `.data`.

The previous OS.c definition imposed 32-byte alignment on the whole OS data
section. This happened to work for EN and JP, but displaced data by eight bytes
in EN rev1 and both PAL revisions. Those retail program addresses are only
eight-byte aligned. Mario Party 4, Melee, Wind Waker and other local SDK donors
also define the program as a private byte array in OSAudioSystem.c, without
that alignment attribute.

Move the existing bytes into OSAudioSystem, restore private linkage, and end
OS.c's data at the last string's terminating NUL. The five-byte gap before the
program remains automatic alignment storage. No function boundary changes.

| Version | OS data start | OS data end | DSP program start | DSP program end |
| --- | --- | --- | --- | --- |
| EN | `8032C360` | `8032C51B` | `8032C520` | `8032C5A0` |
| EN rev1 | `8032CFB8` | `8032D173` | `8032D178` | `8032D1F8` |
| JP | `8032C480` | `8032C63B` | `8032C640` | `8032C6C0` |
| PAL v1.0 | `8032DB38` | `8032DCF3` | `8032DCF8` | `8032DD78` |
| PAL rev1 | `8032DCF8` | `8032DEB3` | `8032DEB8` | `8032DF38` |

## CARD reset record is sixteen bytes

The record contains the callback, priority 127, and two list links: the existing
`OSResetFunctionInfo` contract. The old wrapper appended four zero words to
consume EN alignment padding. Other revisions have eight additional padding
bytes before the next 32-byte-aligned CARD unlock program, so that wrapper
cannot describe the regional layout.

Use the real sixteen-byte record and leave the following zero gap automatic.
Every verified DOL contains the same four-field layout followed by zero padding;
the record starts at `8032EBC0`, `8032F818`, `8032ECE0`, `80330358`, and
`80330518` in the version order above. The next program begins 32 bytes after
the record start in EN/JP, and 40 bytes after it in EN rev1/PAL.

## Linker-generated addresses

Regional configs set `symbols_known: true`, which skips DTK's signature pass.
That left ten relocation sites as raw instruction immediates in each secondary
version. Restore explicit external linker-symbol relocations at the established
sites in OSInit, __OSThreadInit, InitMetroTRK and __init_registers.

The entire normalized functions agree with EN. More importantly, the original
instruction pairs equal the addresses independently calculated from each DOL's
BSS bounds and the existing linker formulas:

| Version | `_stack_addr` | `_db_stack_addr` | `__ArenaLo` |
| --- | --- | --- | --- |
| EN rev1 | `803F90F8` | `803FB0F8` | `803FB100` |
| JP | `803F8598` | `803FA598` | `803FA5A0` |
| PAL v1.0 | `803F9C98` | `803FBC98` | `803FBCA0` |
| PAL rev1 | `803F9E58` | `803FBE58` | `803FBE60` |

The ordinary stack adds `0x10000` bytes, the debugger stack adds `0x2000`, and
the arena starts at the next 32-byte boundary. HA/addi pairs use a signed low
half; HI/ori pairs do not. Existing ArenaHi and stack-end relocations stay intact.
The added targets remain undefined external symbols resolved by the linker;
there are no fixed-address source definitions or linker-script changes.

## Callback scope and PAL refresh

The projector now permits private names in different complete TUs while still
rejecting a collision with another function or data object in the same TU.
It carries proven private linkage with the projected functions. This recovers
SI's AlarmHandler and permits CARD's public OnReset beside OSMemory's private
OnReset. Public or unknown-scope collisions remain conservative.

PAL v1.0's __TRK_get_MSR identity is established by three calls in independently
unique normalized callers: TRKTargetAccessFP, TRKTargetAccessMemory and
TRKInitializeTarget. Its eight-byte body also agrees with EN. The newly supplied
PAL DOL has SHA-1 `c5bb4a7fd3c4aff48c40e282d4d54795c37155f0`; its progress
configuration is refreshed from current EN using the same conservative projector
as the other regions.

## Validation

All five original DOL hashes are verified. For each version, an all-retail link
and a link substituting these seven source objects both reproduce the original
DOL byte-for-byte: OS, OSAudioSystem, OSThread, SIBios, CARDBios, __start and
dolphin_trk. EN also passes `all_source` and the strict matching checksum target.
Only OS.o, OSAudioSystem.o and CARDBios.o change among the compiled source
objects in each version; the other source objects remain byte-identical.

| Version | Exact source units before | After | Additional matched code |
| --- | ---: | ---: | ---: |
| EN | 957 | 957 | 0 |
| EN rev1 | 918 | 922 | 1,468 bytes |
| JP | 948 | 951 | 1,388 bytes |
| PAL v1.0 | 649 | 910 | 15,140 bytes |
| PAL rev1 | 908 | 912 | 1,468 bytes |

These counts use complete code and data agreement per distinct source path,
not stale completion flags. PAL v1.0 additionally gains 237,805 matched data
bytes through the accumulated shared layout/name projection. No previously
exact source unit loses exact status. Padding is left in automatic gaps rather
than attributed to the reset record or OS string pool; raw matched-data totals
therefore drop by 21 bytes in EN/JP while preserving the complete retail image.
This verifies the selected source substitutions, not a full regional source link.

The 107 focused projection, callback, SDA, jump-table and constant-pool tests
pass, including private/public collisions in both record orders, same-TU
function/data collisions, and stable re-rendering.
