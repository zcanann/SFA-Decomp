# Regional small-data recovery

The PAL THP wrapper's 29 unmatched data bytes exposed an incorrect assumption in
`tools/version_progress.py`: it translated every `.sbss` address by the difference
between the two section origins. Equal total zero-storage widths do not establish
equal internal layouts. Normalized code comparisons also hide a reference to the
wrong global when the instruction and relocation shapes agree.

## Retail evidence

`tools/orig/sda_symbol_audit.py` reads each verified retail DOL's unique startup
`lis r13` / `ori r13` pair, then decodes signed r13-relative operands in corresponding
functions. A correspondence requires a globally unique normalized function shape,
or an identical contiguous function sequence between **two** independently unique
functions. Names alone cannot rescue a repeated getter or setter. The report keeps
every instruction witness and reports conflicting destinations without voting.

| Version | Retail r13 base | THP wrapper `.sbss` |
| --- | --- | --- |
| EN v1.0 | `803E31E0` | `803DD664..803DD681` |
| EN rev1 | `803E3E40` | `803DE2E4..803DE301` |
| JP | `803E3300` | `803DD784..803DD7A1` |
| PAL rev1 | `803E4B40` | `803DF01C..803DF039` |

For example, PAL `PlayControl` at `80118998` loads r13 displacement `A4DC`, which
addresses `803DF01C`. Its saved VI callback was incorrectly named at `803DF024`.
That latter address is actually the audio mode, as the DMA callback independently
demonstrates. The wrong ownership made the toolkit globalize the supposedly local
callback as `OldVIPostCallback_803DF024`; changing its spelling alone would have
hidden the cause.

The corrected PAL wrapper owns these offsets:

| Offset | Object |
| --- | --- |
| `00` | `OldVIPostCallback` |
| `04` | Previous audio DMA callback |
| `08` | Audio mode |
| `0C` | Mix source address |
| `10` | Pending source address |
| `14` | DMA buffer index |
| `18` | Prepare-ready message storage |
| `1C` | Loop-completed byte |

The surrounding audio, reader and video-decoder globals share the eight-byte PAL
shift. Earlier and later corridors have other deltas, so this is not a new global
constant to substitute for the old one.

## Layout transitions and projection

The projector now uses the instruction anchors for `.sbss`. It interpolates only
between equal address deltas. At a transition, it bounds ownership by surviving,
individually mapped symbols instead of resurrecting an unanchored leading or
trailing global. Contradictory references, storage-section migration, reversed
storage order and overlapping projected symbols stop generation for review.
Target-only storage outside the evidenced spans remains available for analysis.

Two changes explain important transitions:

- EN rev1 and PAL replace `Objfsa_UpdateWalkGroupPatches`' multiplicative checksum
  with comparison and copying of `0x78` saved flag bytes. Its old checksum is absent
  from their small BSS. The surviving index/count occupy eight bytes at
  `803DE0E0..803DE0E8` and `803DEE18..803DEE20`, respectively. The changed function
  needs further source recovery; this audit does not claim it matches.
- The attract/title-screen small BSS grows from EN's 72 bytes to 80 in EN rev1 and
  PAL. Its beginning and end have different deltas. PAL's game-loop small BSS also
  changes layout. These symbols are projected individually, not by the TU's initial
  offset. Source-used legacy address labels must survive symbol refinement even
  when the TU changes width.

Engine slot 18 owns one four-byte word, directly written by its twelve-byte setter.
Its old EN eight-byte claim included linker alignment padding. Ending that range at
`803DD45C` leaves the four-byte gap before Hcurves and carries the same correction
to the verified secondary configurations. The source object is unchanged and the
strict EN link reproduces retail.

All 1,853 corroborated EN rev1, 1,857 JP and 1,839 PAL `.sbss` symbol addresses now
agree with the retail operands; unanchored symbols remain explicitly unverified.
JP also gains semantic names for previously anonymous, unowned small-data spans.
The existing large `.bss` origin projection remains separate audit work.
Initialized `.sdata` is covered in the follow-up below. PAL rev0's local artifact fails its configured retail hash
and was not used or regenerated.

## Small-BSS matching and validation

PAL gains 205 matched data bytes: track handling 72, the THP wrapper 29, save-select
48, menu polling 16, OS interrupt handling 24, and serial-interface handling 16.
JP's `pi_dolphin` gains 168. Correcting changed layouts and padding also removes old
counts: the net report changes are PAL **+109**, JP **+164**, and **-4** each for EN
and EN rev1 from slot 18's padding. Matched code totals do not change.

Three PAL units newly satisfy the complete objdiff check: `main/thp/dll_3e.c`,
`dlls/engine/59/59.c`, and `dolphin/os/OSInterrupt.c`. Their named small-BSS offsets
also agree with the compiled objects. Resolving all 160 code relocations reproduces
all **4,832 retail code bytes** without normalization. The menu's external
`timeDelta`, still anonymous in PAL's initialized-data config, is independently
anchored at `803DCDCC` by 1,587 operand witnesses for that verification. This is not
a claim that a complete PAL source link has been recovered.

All four `all_source` builds pass, with all 991 EN and 988-per-secondary compiled
source objects byte-identical to the baseline. The strict matching EN DOL checksum
passes. No compiler profiles or C/C++ source changed.

Useful checks:

```sh
python3 tools/orig/sda_symbol_audit.py GSAP01_rev1 --section sbss
python3 tools/orig/sda_symbol_audit.py GSAP01_rev1 --unit main/thp/dll_3e.c --all --json
python3 -m unittest discover -s tools -p test_sda_symbol_audit.py
python3 -m unittest discover -s tools -p test_version_progress.py
```

## Initialized-data follow-up

Raw operands exposed 86 initialized-small-data discrepancies in PAL, 12 in EN
rev1 and four in JP. The projector now restores individual symbols only when a
unique operand-backed destination also contains identical initialization bytes.
Whole TU ranges additionally require a directly referenced start, consistent
interior operand offsets and identical bytes throughout. Repeated float values
alone are not enough to choose a boundary.

PAL's fourteen effect phase pools occupy `803DD160..803DD240`, sixteen bytes per
unit in order: 26, 27, 29, 30, 31, 32, 33, 34, 35, 41, 42, 43, 44, 45. The old
boundaries drifted four, then eight bytes through repeated 0.1/0.3 initializers.
The following engine-23 range starts at `803DD240`; its regional width differs
from EN and is retained. Recovered timing names include `timeDelta` at `803DCDCC`.
PAL's game-loop initialized storage remains 24 bytes versus EN's 32.

Equal TU width also does not establish an identical internal layout. Both options
ranges are eight bytes, but PAL `gOptionsActivePanel` occupies `803DD3ED`, five
bytes after the range start. The preceding bytes are `00 01 03 05 02`; their role
remains unknown. The renderer now refuses linear symbol replacement when observed
operand offsets contradict it.

An EN address-style source name can collide with an unrelated regional label at
that same numeric address. The projector preserves that regional storage and uses
the imported symbol's regional address label instead. Two such collisions remain
reported as name mismatches in each of EN rev1 and JP; they are not permission to
rename unrelated save-select/player storage. The final audit reports 875 exact
EN rev1, 896 exact JP and 870 exact PAL initialized-data addresses, with 170, 149
and 177 unanchored symbols respectively. PAL has no remaining corroborated address
mismatches. These counts do not verify unanchored globals or relocated pointer
initializers: pointer targets require their own relocation checks.

### Effect flags and raw relocation verification

Five assignments in engine slots 27, 32, 33 and 45 cast `randomChanceOneIn` to a
behavior mask. Its EN address happens to equal `0x80080100`, but all four verified
retail versions store that same literal mask even when the RNG function moves.
The source now combines the existing `EXPGFX_BEHAVIOR_RANDOM_XZ_JITTER`,
`EXPGFX_BEHAVIOR_BILLBOARD_USE_PITCH` and `EXPGFX_BEHAVIOR_ALPHA_PULSE` flags.
Each version blocks relocation discovery at just those five eight-byte lis/addi
ranges. Genuine RNG calls retain their relocations.

Resolving every source code relocation for all fourteen units reproduces
**127,120 retail text bytes through 5,435 relocations per version**. Resolving their
initialized sections also reproduces **5,560 bytes through 562 data relocations
per version**, including descriptors and jump tables. Both comparisons are exact
without instruction or symbol normalization in EN, EN rev1, JP and PAL rev1.

Ten PAL units newly pass the complete objdiff gate: 26, 27, 29, 30, 31, 32, 33, 34,
35 and 45. Together they add 160 matched data bytes; game-loop initialized data
adds another 24, for **+184 PAL matched data bytes**. Matched code and total code/data
denominators do not change. EN, EN rev1 and JP report totals are unchanged.

All four source builds and the strict EN retail checksum pass. Only the four
source objects containing the flag fixes change per version; the other 987 EN and
984-per-secondary objects remain byte-identical. The 54 projection/audit tests
pass. PAL rev0 remains excluded because its local artifact fails the configured
retail hash.

```sh
python3 tools/orig/sda_symbol_audit.py GSAP01_rev1 --section sdata
python3 tools/orig/sda_symbol_audit.py GSAP01_rev1 --section sdata --all --json
```
