# OSFont glyph-patch initializer

`OSLoadFont` patches four rows of the `T` glyph after decoding the SJIS font.
The source previously modeled its initializer as two public `const u32`
definitions and copied them into a local halfword array through casted word
loads and stores.

The Sunshine and Pikmin 2 SDK sources both express the patch as a local
four-halfword initializer. The recovered SFA spelling is:

```c
u16 glyphRows[4] = {0x2ABE, 0x003D, 0x003D, 0x003D};
```

The existing loop stores these words into glyph rows 4 through 7. Naming the
array `glyphRows` and spelling the character as `'T'` records those direct uses.
The local remains writable, as in the contemporary Sunshine donor; no type,
width or const-qualification change is needed elsewhere.

MWCC now emits one private eight-byte initializer template in `.sdata2`, replacing
the two fabricated public word identities. Its bytes are exactly
`2ABE003D003D003D`, and the compiler emits the same stack initialization and
glyph-copy instructions. Section sizes and alignment remain unchanged:
2,924 text bytes, 2,826 data bytes, two small-data bytes, 16 small-BSS bytes and
eight small-constant bytes. All allocated section bytes are identical in every
version; symbol and relocation identities now describe the single local template.
The global constant declarations, redundant externs
and casted initialization accesses are removed; the retail symbol annotations
remain address anchors.

All five versions retain seven exact functions and all 2,852 data bytes in
direct objdiff comparisons with completion annotations disabled. Substituting
only the OSFont source object into each retail link reproduces the verified
original DOL, establishing that no other unit needs the removed public names.
All five native matching builds and `all_source` builds pass. No compiler
profile, TU boundary, source-completion flag or progress count changes.

Donor sources inspected:
`reference_projects/super_mario_sunshine/src/dolphin/os/OSFont.c` and
`reference_projects/pikmin2/src/Dolphin/os/OSFont.c`. Both remain unchanged.
