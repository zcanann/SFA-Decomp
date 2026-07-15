# SharpClaw / WarpStone conversion-pool boundary

`SCchieflightfoot` and WarpStone cannot currently be promoted as independent
source objects even though their functions are instruction-exact. Both use the
same signed-integer-to-double conversion constant at `0x803E5490`.

## Retail evidence

- `SHthorntail_updateDustEffects` references the constant at `0x801D698C`,
  `0x801D6A04`, and `0x801D6AE8`.
- `warpstone_update` references it at `0x801D77CC` and `0x801D781C`.
- Retail contains one eight-byte object at `0x803E5490`, currently carved into
  `SH/dll_01B0_shswapston.c` as `@279_803E5490`.
- The surrounding retail text is ordered as the `SCchieflightfoot` region,
  `SClantern_advanceAnimEvents`, and then the WarpStone region. Debug-side source
  order further divides the WarpStone code between `SCcollectables.c` and
  `SCanimobj.c`. This is broader than a simple two-file ownership mistake.

## Source-link experiment

Compiling either current C file naturally emits a local eight-byte `@279`
pool. Promoting only WarpStone leaves the retail assembly object for
`scchieflightfoot` with an undefined reference to `@279_803E5490`. Promoting
both files links, but adds a second eight-byte pool: the DOL `.sdata2` size
increases from `0x28` to `0x30`, and every following small-data relocation is
shifted by eight bytes. The strict checksum therefore fails.

## Boundary conclusion

The retail constant belongs to a shared DLL-level compilation or sublink pool,
not independently to either current C object. Moving the existing split only
changes which carved object owns the sole post-link bytes; it cannot reproduce
the pre-link sharing. An honest promotion needs the original DLL grouping (or
equivalent build support that reproduces its shared pool). Do not solve this
with a symbol alias, forced section, padding, or a synthetic conversion shim.
