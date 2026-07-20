# SFA-Decomp

Decompilation of Star Fox Adventures (GameCube): recover plausible original C that byte-matches the
retail binary. Main lib compiled with MWCC GC/2.0; audio/MSL with 1.2.5n.

## Goal & rules
- Recover the **plausible 2002 C** a Rare dev would have written. Inline `asm{}` is banned outside
  `src/dolphin/`. Inside SDK code, the only exception is paired-single `psq_l`/`psq_st` when MWCC has
  no intrinsic and a known-good donor or original binary proves the sequence. A clean-C 90% beats an asm 100%.
- Match % truth = `report.json` `fuzzy_match_percent`. Diff tools locate divergence; they don't certify it.
- **Fresh eyes.** This file is deliberately tiny and is **not** a catalogue of techniques or solved
  cases — that omission is on purpose. If a fix isn't here, that means nothing: read the target asm and
  derive it yourself. Every function is matchable; an unsolved one is a lever not-yet-found, never an
  impossibility.

## The project itself is the playbook
The real knowledge lives in matched code, not in this file — that's why this file stays short. To
produce a particular asm shape, find code that already emits it and read the C behind it:
- **This repo's own matched functions** — grep `src/` for the construct, or disassemble a matched
  `.o` that has the shape you want (objdump command below) and open its source.
- **The MP4 reference decomp** (`reference_projects/marioparty4`, fully matched, same MWCC family) —
  a large known-good C↔asm corpus; read its source for how a given shape was written.
- **The GC/2.0 reference-asm corpus** (`tools/refcorpus/`, see `docs/refcorpus.md`) — ~42k funcs of
  SFA-adjacent C (MP4 + Diddy Kong Racing + Jet Force Gemini) recompiled with *our* compiler across
  the peephole×scheduling profiles. Search asm↔C both ways:
  `python3 tools/refcorpus/search_corpus.py --asm '<regex>' --show-c` or `--csrc '<c regex>'`.
A fix derived from a real matched example beats any written recipe, and the corpus only grows as the
project matches more.

## Build & verify
- Rebuild one unit + the report:
  `rm build/GSAE01/src/main/<path>.o && ninja build/GSAE01/src/main/<path>.o && ninja build/GSAE01/report.json`
- `ninja; echo EXIT=$?` — must be `EXIT=0` before any commit. (No `timeout` on this box: it is
  not installed, so a `timeout N ninja` gate returns 127 and never builds.)
- Paired-single disasm: `build/binutils/powerpc-eabi-objdump -M gekko -drz` (stock objdump mis-decodes PS as VSX).
- Tools are in `tools/` — start with `function_objdump.py <unit> <symbol>` (full target asm) and `ndiff.py`.

## Don't break `main`
- Retail target objs (`build/GSAE01/obj/...`) are READ-ONLY — never rebuild or delete them. Only the
  source objs (`build/GSAE01/src/...`) are yours to build.
- Branch off main; rebase + `ninja EXIT=0` before each commit; commit only when asked. One owner per `.c`.
- Edit SJIS-bearing files byte-wise (python rb/wb). Never `git stash` in a worktree — use `git checkout -- <file>`.

## Banned constructs (game code: `src/main/`, `src/track/`)
These are match-hacks, not plausible 2002 source. They were purged repo-wide (see
`docs/HACK_AUDIT.md`, tag `pre-hack-purge`) and MUST NOT re-enter:
- **Any `#pragma`** — per-function pragma sandwiches of every kind (peephole/scheduling/dont_inline/
  inline_max_size/opt_*/ppc_unroll_*/optimization_level/fp_contract/explicit_zero_data/force_active/
  exceptions). Inline pragmas are banned; pragmas may only be configured at the TU level via
  `configure.py` cflags.
- **`goto`** — write structured control flow.
- **`__declspec(section ...)`** and any section-forcing data placement.
- **Match-volatiles** — `volatile` or `*(volatile T*)&` puns used to block CSE/hoisting. `volatile`
  is allowed only for genuine hardware/interrupt semantics (GX FIFO, hardware registers).
- **Pool-reconstruction consts** — `lbl_8XXXXXXX`-named const defs read via `*(f32*)&`; write plain
  literals. This includes the **`const union { f32 f; } lbl_x = { V };` + `lbl_x.f`** disguise (a
  named-`.sdata2` float that blocks folding to force the pool symbol) — banned; write the plain
  literal `V`. (A `union { f32 f; u32 u; }` used via BOTH `.f` and `.u` for a genuine int↔float
  bit-reinterpretation is a different thing and is not this ban.)
A unit that cannot match without one of these stays `NonMatching` (or awaits a TU re-split) — that is
the accepted trade. Historical per-hack shapes and costs are recoverable via `docs/HACK_AUDIT.md`.

**Why this keeps getting re-introduced, and the real fix:** `tools/unit_score.py` (objdiff one-shot)
UNDERCOUNTS near-matches — it flags anonymous `@N` vs named `lbl_` `.sdata2` pool relocations as a diff
even when the bytes are identical. Agents then "fix" the phantom diff with a pool-reconstruction hack.
The truth metric is `report.json` `fuzzy_match_percent` (rebuild the unit `.o`, then
`ninja build/GSAE01/report.json`); a plain literal usually scores identically. Guidance: **when the
only diff is `@N`-vs-`lbl_` pool naming, it is almost always already byte-identical — do NOT hack it;
trust report.json.** If the pool ORDER genuinely differs (report.json actually drops with plain
literals), that is a TU-boundary artifact — leave the unit `NonMatching`, do not reconstruct the pool.

## House rules
- NEVER write comments unless explicitly stated otherwise.
- When updating comments NEVER track history, stuff like "used to be named x" always keep comments current.
- `include/main/gamebit_ids.h`: a NEW `GAMEBIT_*` id ALWAYS goes in the unordered (Rena-imported)
  section, inserted in ascending-id order — NEVER interleave it into the chronological/story-ordered
  section at the top, and NEVER split a comment from the entry it describes. An id may be promoted into
  the ordered section ONLY once its story/activation position has been established by directly debugging
  the game in Dolphin.

## A few MWCC facts (high-frequency only — NOT a map; derive everything else fresh)
- Compare opcode tracks operand width/sign **when it feeds a branch**: `u16`/unsigned → `cmplwi`, `int`/`long` → `cmpwi`. Type the local/field to the field width. (Inert against a runtime `int` operand.)
- Single-bit clear: write `x &= ~0x80` (→ `rlwinm`), not `x &= 0xff7f` (→ `andi`).
- `u8` not `char` for a byte loaded and stored without arithmetic — drops a spurious `extsb`.
- **Saved-register homes: two populations, each with its own key** (same law for `r14..r31` and `f14..f31`). **Load class** — a value materialized *into* its home by a load, a computation or a constant — is keyed on **declaration order**, assigned `r31` downward (first-declared → `r31`); its definition order, use order and use count are all inert. **Copy class** — a value copied from a fixed ABI register, i.e. an incoming parameter or a call return — is keyed on **definition (program) order**, assigned from the *bottom* of the band upward; its declaration order is entirely inert. Probes: 24 decl permutations of four load-class locals give 24 distinct outcomes, the same 24 over four call results give **one**. The two populations take disjoint sub-bands and stay independently steerable when mixed. A value with **no named local behind it** (a compiler temp, a spill reload, an array base) is in neither and is unreachable from source — give it a name to move it. Sweep with `tools/permsweep.py` (gates on bytes via `tools/fnbytes.py` — never on tool silence).
- **A same-length register permutation in the SCRATCH band (`r3..r12`) is a per-TU FLAG signature, not an allocator wall.** Copy/constant propagation reorders the values the allocator sees, permuting scratch homes with the instruction stream held identical — a 10-line probe flips `r4`/`r5` on nothing but `-opt nopropagation`. Probe it **per function** with `tools/fn_flag_probe.py <unit>`; when functions in one unit want different profiles the unit merges TUs and needs a split (that sweep is done — 42 functions, 22 units, all splits, no flag flip left).
- `f32 fn(f32)`, not `double fn(double)`, for single-precision helpers — avoids an `fmul`+`frsp`.
- A single-bit flag written as a C bitfield (`u8 x:1`) compiles to `li; rlwimi`, not a manual `|= mask`.
- FP compare feeding a branch → write the plain operator (`a >= b` → `fcmpo`+branch). A stored/returned float-bool uses a different form.
- Reordering a callee's parameter list is **register-neutral** (the ABI assigns registers by type, not declared order) — use it to match the target's prologue-save / caller arg-emission order.
- Distrust raw derefs/casts — the original was almost always a struct/union/typed array. Try `arr[i].field`, a bitfield/union overlay, or a typed pointer first; it often fixes addressing and coloring, not just readability.
