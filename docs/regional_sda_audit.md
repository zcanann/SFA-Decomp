# Regional small-BSS recovery

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
The existing large `.bss` origin projection and initialized `.sdata` discrepancies
are separate audit work. PAL rev0's local artifact fails its configured retail hash
and was not used or regenerated.

## Matching and validation

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
