# Investigation: cross-function compiler state within a TU (GC/2.0)

Status: **validated by controlled experiment** (player.c, 2026-07-07 session).

## The finding
The conversion-temp/pool machinery (the 0x4f9e30 slot assigner + CodeGen temp pool
0x5ddc98, see INVESTIGATION_addr_init_copy sessions 3-6) does **not** behave as a
purely per-function system: the same function text, compiled in the same TU, produces
**different temp-slot claim orders depending on which functions precede it in the file**.

Proof harness: `decompctx` output for player.c compiles standalone (the .ctx contains
the whole TU). Extracting fn_802ABAE8's g-clamp ternary region:
- compiled at its real file position → conv temps claim descending fresh slots
  (44/40, 36/32, 28/24) — the *current mismatched* shape;
- the **identical text** moved before the first function definition → conv temps
  re-claim (44/40, 44/40, 36/32) — the *retail* shape.

Similarly the fn_802AD2F4 / staffShootFireball / fn_802B1E5C "GPR-arg deferred past
the first FP-arg load" mismatches all reproduce **target-like** in isolated probes and
mismatch **only in situ**.

## Consequences for matching work
1. A function can be blocked by *invisible IR differences in earlier functions* even
   when those earlier functions byte-match: byte equality does not imply temp-pool
   trajectory equality.
2. Byte-neutral source spellings are not interchangeable: they can change the pool
   state seen by later functions. Prefer the most plausible spelling even at 100%.
3. Standalone-probe results (tools/mwcc_re harness, refcorpus shapes) demonstrate
   *reachability*, not in-situ behavior. Always re-measure in the real TU.
4. Any file-snapshot base (permuter, tu.c experiments) goes stale the moment the tree
   changes anywhere in the file: revalidate found mutations in-tree before trusting.

## Related class instances catalogued this session (player.c)
- `~KLL` 64-bit mask literals: the u32-lvalue zext high word materializes `li r?,0`
  which is dead in retail but in our builds gets VN-reused by a later `= 0` /`= -1`
  store, hoisting a constant web to the common dominator and shifting colors
  (playerDoHitDetection head `stb 607`, playerStateAttack `stb 2253`, playerRender,
  player_SeqFn). Signed lvalues emit a surviving dead `srawi` instead (playerState19,
  playerState1B). Neither spelling reaches the retail shape when a same-value store
  follows; sites where nothing reuses the zero match fine. Both directions were
  probe-validated (m2/m7/m8 series).
- FP-select flush: a nested FP ternary whose operands are **extern float loads**
  releases all claimed conversion temps; the same ternary with **float literals**
  does not (probe4-13 series). This is the lever that finished fn_802ADE80, but it
  is two-sided — some functions need the flush (fn_802ABAE8, fn_802AC32C regressed
  with literals).

## Tooling
- `decomp-permuter` works on the full-TU ctx base (preprocess with `cc -E -P` first;
  pycparser rejects comments/directives). Patch applied to
  `src/objdump.py::objdump` honouring `PERMUTER_FUNC=<symbol>` to slice the
  disassembly to one function: scores then track the per-function diff exactly
  (whole-object scores do NOT transfer to per-function fuzzy %).
- Validated transfer example: playerState25 98.77→98.97 from a permuter-found
  two-step `vx` split + clamp field re-read.
