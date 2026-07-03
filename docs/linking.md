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

## Linking the data side (harder)

Most matched-but-unlinked code is blocked by *data*, not code. `matched_code` is
~72% but `complete_code` (linked) is ~13%: the gap is 100%-matched units whose
built object emits `.data`/`.sdata2`/`.rodata` the retail per-unit object lacks,
because the retail split never attributed that unit its data. To link one you
must add the exact data range(s) to its `splits.txt` entry (see any complete DLL,
e.g. `dll_020C_wmspiritplace.c`, for the format):

```
main/dll/foo.c:
	.text       start:0x... end:0x...
	.data       start:0x... end:0x...     # the unit's own data, reattributed
```

Derive the range by correlating relocations: for each symbol the *built* object
defines in a data section, find the *retail* object's `.text` reloc at the same
instruction offset — it names the real symbol, whose address (from `symbols.txt`)
gives the range. `base = symaddr - built_symbol_offset`.

Three walls make this a per-unit decomp task, not a bulk flip:

- **Shared `.sdata2` constant pools (the big one — ~100 units, ~350k code).**
  Float / int-magic constants live in a pool (`lbl_803Exxxx`) currently provided
  by an auto data unit. A unit's object emits its copy as an anonymous *local*,
  but other units reference the same constant as a *global* — attributing the
  pool range to one unit makes those globals vanish (`undefined: lbl_...`).
  Reproducing retail needs the constant referenced externally, which the source
  can't express for anonymous literals. Not fixable by splits alone.
- **Layout mismatch.** Our source's data order can differ from retail's — e.g. a
  unit whose object has `jumptable` + `descriptor` contiguous while retail
  interleaves a neighbour's data between them. The built section is one block, so
  it can't map to a non-contiguous retail region.
- **Relocated data.** A `.data` jumptable of code pointers is all-zero in the
  object (filled at link). Even with the right range it can still miss the SHA1,
  so the DOL check remains the only proof.

Net: only a handful of units have data that is uniquely owned, contiguous, and
unattributed — those link cleanly (this pass linked 6 via derived splits). Moving
the linked % substantially further needs either coordinated multi-unit relinking
of whole `.sdata2` pools (structural) or matching much more data first
(`matched_data` is only ~3.7%).
