# `mapLoadDataFile` matching

`main/pi_dolphin.c` is 100% code and data (57/57 functions) as of 2026-09-26 and links as
`MatchingFor("GSAE01")`.

## The residual was a declaration, not register allocation

For months `mapLoadDataFile` sat at 99.71% with an identical instruction stream and a
colouring-only residual. The slot accessors went through named "biased" locals
(`slotPtrAddr = (slot << 2) + ((u32)&tbl->ptrs[0] + 0x6A28)`, dereferenced at `- 0x6A28`).
That spelling reproduced retail's `addis`/`add` web with the low offset folded into each load,
but it made the web a declared object. Retail's web is a compiler temp, so the colouring differed.

The biased locals existed because plain `tbl->ptrs[slot]` made the GC/1.3 IR share the whole
address as one temp, adding an `addi` that retail doesn't have. Standalone probes pin the
trigger down to one declaration:

| Base object | Repeated `t->ptrs[slot]` |
| --- | --- |
| `extern u8 gA[];` cast to the struct type (unsized) | full address shared, `addi` + `lwz 0(r)` |
| `extern u8 gB[0x160];` (sized), with or without `&` | folded, `lwz -27176(r)` (retail) |
| any struct-typed object, `extern` or defined | folded (retail) |

`gResourceFileTable` was declared `extern u8 gResourceFileTable[];`. Giving it its size
(`[0x160]`, matching its definition) lets every accessor use the plain typed form. The
index-first spellings `((s) << 2) + (u32)tbl->ids` (and `<< 1` for owners, `slot << 2` for
ptrs) reproduce retail's `slwi` before `addis` order.

## Linking the unit

Promoting the unit exposed a latent link problem. `.sbss` padding `sPiUnused1` was `static`,
so FORCEACTIVE couldn't keep it and the linker stripped it, shifting every later `r13`
offset by 4. It is now global and listed under `force_active` in `config/GSAE01/config.yml`,
like `sPiUnused0/2/3`.

## Method

The instruction stream matched long before the registers did. Captures from
`tools/tricky_backend_trace.py`, retail-register projection, a replay of the colourer and an
LLDB hook on the IR range splitter showed which objects needed different numbering. Probes
then showed the numbering came from the IR sharing decision above.
