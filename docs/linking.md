# Linking units into main.dol

SFA is a single static DOL: every unit (including the `dll_*` modules) is
linked into `build/GSAE01/main.dol`, which is verified against one SHA1
(`config/GSAE01/build.sha1`). A unit is **linked** when `configure.py` marks it
`MatchingFor("GSAE01")` (or `Matching`) instead of `NonMatching`: dtk then links
*your* built object into the DOL instead of the retail object split from the
original. If the DOL still hashes correctly, the unit is done.

```
# flip in configure.py:  Object(NonMatching, ...) -> Object(MatchingFor("GSAE01"), ...)
python3 configure.py
ninja build/GSAE01/ok        # LINK -> DOL -> CHECK; EXIT 0 + "main.dol: OK" == linked
```

`ninja` alone only builds the DOL; it does **not** run the SHA1 check. Always
build the `build/GSAE01/ok` target to verify.

## 100% objdiff is necessary but not sufficient

objdiff's `fuzzy_match_percent` compares sections symbol-by-symbol. A unit can be
100% and still refuse to link, because the link cares about things objdiff
ignores. The failure modes seen so far:

- **Extra/short section.** The built object emits a `.data`/`.sdata2` the retail
  object doesn't (or a different size). objdiff scores the matched sections 100%,
  but the surplus bytes shift every later section and ~140k DOL bytes change.
  *Cause:* data the original kept in another TU / another section. *Detect:*
  compare built-vs-retail section sizes.
- **Unresolved synthetic label.** Source still references a `lbl_803DD518` /
  `fn_8004E0FC` style label. objdiff resolves it by address so it looks matched,
  but the linker resolves by name and aborts (`undefined: 'lbl_...'`). *Fix:*
  point the extern at the real named symbol (here `gCamcontrolActiveActionId`).
- **bss / common-merge shift.** Two objects each pass every static check yet,
  linked together, move the `.bss`/`.sdata` base a few bytes (common-symbol
  merging is cross-object). Nothing local predicts it — only the link + bisect
  finds it.

## Workflow that scales

1. `python3 tools/link_scan.py` — lists 100%-objdiff `NonMatching` units whose
   built object matches the retail object section-for-section (sizes + bytes)
   with all undefined symbols resolvable. This filters out the first two failure
   modes above.
2. Flip the whole list, `ninja build/GSAE01/ok`.
3. On failure, **bisect**: a passing subset proves *every* unit in it links (the
   DOL is byte-perfect), so accept passing halves wholesale and recurse only into
   failing halves to isolate the few shift-causing culprits. ~log2(N) links.
4. Re-verify the full accepted set together before committing (rules out
   pairwise interactions), then commit the `configure.py` flips.

The first linking pass took 133 scanner candidates to 129 linked units; the 4
that didn't were 2 bss-shift culprits (found by bisection) and 2 needing a
synthetic-label rename in source.
