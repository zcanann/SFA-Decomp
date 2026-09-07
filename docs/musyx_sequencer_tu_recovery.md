# MusyX Sequencer Translation Unit Recovery

## Evidence And Scope

The EN sequencer is one contiguous 26-function island, from `ResetNotes` at
`0x8026BF54` through the end of `seqInit` at `0x8026F53C`. It was represented
by six compiled fragments plus two zero-size placeholder units. Retail code
in `seqStop`, `seqSpeed`, `seqMute`, `seqVolume`, `seqCrossFade`, `HandleEvent`,
and `seqInit` addresses sequence state and MIDI priorities through a common
`seqNote` base, across those artificial source boundaries.

The three native arrays occupy the following contiguous BSS allocations:

| Array | EN Address | Size | Shape |
| --- | --- | --- | --- |
| `seqNote` | `803AF550` | `1400` | 256 records of `14` bytes |
| `seqInstance` | `803B0950` | `C340` | 8 records of `1868` bytes |
| `seqMIDIPriority` | `803BCC90` | `100` | 8 by 16 halfwords |

Sizes and addresses above are hexadecimal. Some retail accesses use the
individual array symbols; common-base addressing does not establish a C
aggregate. The former `SynthVoiceRuntime` overlay instead cast the first
array's `0x1400` allocation to a `0xD840` record spanning separate definitions.

[AxioDL's MusyX sequencer](https://raw.githubusercontent.com/AxioDL/musyx/main/src/musyx/runtime/seq.c)
independently corroborates the three native arrays, their dimensions, a
leading `ClearNotes` helper, and this routine order. This is library-lineage
evidence, not a recovered SFA source artifact or proof of identical source
syntax. No literal retail filename leak establishes `seq.c` here.

The merged unit preserves all existing outer section boundaries:
`extab 80005620..80005688`, `extabindex 80005CC0..80005D5C`,
`.text 8026BF54..8026F53C`, `.data 8032ED80..8032EDD0`,
`.bss 803AF550..803BCD90`, `.sbss 803DE218..803DE238`, and
`.sdata2 803E7780..803E7798`. Neighboring units are unchanged.
Secondary-version projections likewise merge exactly the existing contiguous
section unions; unrelated generated symbol and mapping changes are excluded.

## Source Recovery

`seq.c` owns the native arrays and uses indexed `SynthVoice` members rather
than the overlay. Pending crossfade offsets `22B4/22DC/22E0` relative to the
old common base become `syncCrossInfo/syncSeqIdPtr/syncActive` at
`EB4/EDC/EE0` in the owning sequence. Section accesses use the existing
`0x38`-byte record at `SynthVoice.section`, offset `14E8`.

`seqStop` reuses the actual `KillNotes` helper. `seqVolume` walks the native
track-volume array. State names now distinguish active and paused sequences.
The empty placeholder and unassigned duplicate queue helpers are removed.
Layout assertions cover the allocations and recovered offsets.

The real, called `ClearNotes` helper precedes `ResetNotes`; MWCC's first-use
BSS emission then places all three native arrays correctly. Its out-of-line
body is 236 bytes, followed by alignment padding, and is dead-stripped from
the link. No section placement directive or substitute aggregate is used.

## Match And Verification

Against `12b1977406`, exact sequencer functions fall from 24/26 to 21/26:
`seqVolume`, `seqCrossFade`, and `HandleTrackEvents` lose exactness;
`seqStop` and `seqInit` were already non-exact. Matched code falls by 2,372
bytes and matched exception data by 260 bytes. Total generated text is
14,540 bytes versus retail's 13,800, including the unused helper and padding.

Ordinary `.data`, `.bss`, `.sbss`, and `.sdata2` have exact sizes and bytes.
All shared named storage symbols retain retail offsets and sizes; retail
labels for compiler-generated literals, padding, and the jump table do not
exist as named C declarations. All 20 jump-table relocation destinations
were independently audited. Exception sections retain their sizes but not
their contents. Both the strict DOL checksum and `ninja all_source` pass;
the merged unit remains `NonMatching`, so the strict link uses its retail
object and is not proof that the reconstructed C matches.

The compiler remains MusyX's GC/1.2.5n with `-inline auto` and
`-fp_contract off`. The merger permits three `seqGetPrivateId` calls in
`seqCrossFade` and `HandleMasterTrack` in `HandleTrackEvents` to inline where
retail calls out of line. Blanket `noauto` inhibits other needed inlining;
it is not retained. Recovering plausible source with the mixed retail call
topology remains open, as do the pre-existing local/type artifacts.

`python tools/test_musyx_sequence_runtime.py` checks PPC BSS layout and runs
143 host scenarios at both O0 and O2 (286 executions): initialization,
active/paused list removal, note recycling, direct/deferred speed and mute,
volume groups, pending crossfades, and all sixteen section-loop restarts.
Whole-array comparisons check unrelated-field preservation. Host tests use
host-width pointers and mock external calls, not emulated PPC execution;
they do not cover immediate crossfades or the full audio scheduler.
In-memory negative controls produced 6, 16, 64, and 64 failures respectively
for omitted note killing, a shortened speed loop, wrong crossfade activation,
and a broken master-track cursor reset, with no compilation errors.

Only the new sequencer object differs from the prior all-source object
snapshot; shared-header consumers retain byte-identical objects.
