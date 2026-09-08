# Time-list prompt color recovery

EN `timeListDraw` converts the pulse expression with `fctiwz`, loads its signed
32-bit result, and copies that result directly into the RGB arguments of
`gameTextSetColor`. It does not narrow the pulse or the selected prompt colors
to bytes. The existing text API takes `int` channels and narrows them inside
the setter, both for immediate colors and deferred commands.

The pulse brightness and the two prompt brightness locals are therefore `int`,
not `u8`. The normal amplitude/bias values of 55 and 200 produce 145..255;
their range does not establish byte storage. An unsigned full-width pulse is
also wrong: GC/1.3 emits `__cvt_fp2unsigned` instead of retail's `fctiwz`.

Against `f958633028`, this restores the entire 812-byte function from 99.31035%
to 100%. Engine DLL 0 improves from 99.861145% to 99.8686% overall fuzzy match.
Only six instruction words in this function change. All other function bodies,
allocated non-text sections, and named symbol layouts are identical. The 4,633
relocations keep their locations, types, addends, and targets; 85 anonymous
literal names are renumbered, without changing their section offsets.

`tools/test_gameui_time_list_colors.py` executes the production renderer with
mock drawing, sine, time-formatting, and game-bit APIs. Its 74 calls across host
O0/O2 check prompt selection, signed truncation, RGB argument width, alpha,
restoration to white, 16-bit angle wrap, and the paused early return. Values
outside the normal pulse range deliberately expose premature byte narrowing:
changing only the two selected-color locals back to `u8` causes 32 failures.
This harness does not verify texture rendering, sine accuracy, or time strings.
Its chosen arithmetic inputs are exactly representable; host contraction is
disabled, so it does not test rounding-sensitive cases of retail's `fmadds`.
The existing 1,028-case color-setter harness checks the actual narrowing in
both immediate and deferred modes.

The unit remains NonMatching for other functions. Its strict-link checksum
therefore does not validate this source change; the exact function comparison
and unchanged object data provide the relevant target evidence.
