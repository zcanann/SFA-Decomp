# Regional insertions between initialized small-data pools

PAL model lighting now matches completely after correcting its `.sdata2` end
from `803E0170` to `803E0168`. Its 58 functions already matched; the incorrect
pool boundary had included eight bytes used by the neighboring game loop.

## Retail evidence

| Pool | EN | PAL rev1 |
| --- | --- | --- |
| `main/modellight.c` | `803DE750..803DE7A8` | `803E0110..803E0168` |
| Progressive-scan conversion bias | absent from this gap | `803E0168..803E0170` |
| `main/gameloop_main.c` | `803DE7A8..803DE7BC` | `803E0170..803E0184` |

The complete 88-byte lighting pool agrees with EN and the compiled source.
Its 102 direct r2 loads reference 19 distinct constants within that range.
The next eight bytes contain `4330000000000000`, the unsigned-integer conversion
bias loaded by PAL `askProgressiveScanMode` at `8001FDE8` and `8001FE54`.
Those are the only direct r2 loads into the incorrectly included bytes.
The regional game-loop source does not yet emit this pool, so those bytes remain
in an automatic gap rather than being assigned to a source object prematurely.

## Projection fix and limits

The EN lighting end and next pool start share one address. PAL inserts another
pool between them, so that single EN address needs two different target edges.
The projector previously discarded conflicting initialized-data edge evidence
and could then widen lighting to the following pool's start.

`recover_sdata_layout` now retains independently witnessed per-unit extents as
well as unambiguous global edges. The existing unique operand, interior-offset
and complete-byte checks still apply. `port_coherent_units` uses these extents
only when the TU's mapped retail code spans retain their sizes and normalized
instruction sequences. Its automatic four-byte gap extension also respects
these witnessed ends. This applies to both `.sdata` and `.sdata2`.

The unchanged-code condition matters for WCLevelCont. EN and JP have a 52-byte
pool, while EN rev1 and PAL have 56 bytes. The regional addition is a real
`300.0f` constant (`43960000`), loaded by PAL `wclevelcont_init` at `802279B4`.
Although the original 52-byte prefix still agrees, the retail code changes and
uses the extra constant. The projector preserves the larger regional extents:
EN rev1 `803E7A40..803E7A78` and PAL `803E87A0..803E87D8`.

## Validation

- PAL lighting matches all 10,768 code bytes and 496 data bytes, including its
  88-byte constant pool. Matched data increases by 88 bytes; completed units
  increase from 906 to 907. The overall data denominator is unchanged because
  the excluded eight bytes remain represented by an automatic gap.
- Both the all-retail link and the link substituting lighting source reproduce
  the verified PAL DOL SHA-1 `c1a6ccdc61c7e719e20ea7cc59c8de09fd183e66`.
- All 988 PAL source objects remain byte-identical. PAL `all_source` passes;
  EN `all_source` and the strict retail checksum also pass.
- Full projections preserve EN rev1 and JP splits and reproduce the single PAL
  lighting correction. No unrelated projected symbol changes are included.
- The 79 SDA, version-projection, jump-table and pool-audit tests pass, including
  inserted four/eight-byte pools and a changed TU retaining its larger pool.

```sh
python3 tools/verify_source_link.py GSAP01_rev1 main/modellight.c
```
