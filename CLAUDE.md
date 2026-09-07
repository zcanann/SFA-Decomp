# SFA-Decomp

Decompilation of Star Fox Adventures (GameCube): recover plausible original C that byte-matches the
retail binary. Main lib compiled with MWCC GC/2.0; audio/MSL with 1.2.5n.

## Goal & rules
- Recover the **plausible 2002 C** a Rare dev would have written. Inline `asm{}` is banned outside
  `src/dolphin/`. Inside SDK code, the only exception is paired-single `psq_l`/`psq_st` when MWCC has
  no intrinsic and a known-good donor or original binary proves the sequence. A clean-C 90% beats an asm 100%.
  The two retail assembly islands are handled as decomp projects handle authored asm, not as C to be
  matched: `src/main/zlb.s` is an assembled TU and `modelAnimBuildJointMatrices` in `src/main/render.c`
  is an MWCC function-level `asm` body, both byte-verified (`docs/foreign/`). Adding a third needs the
  same provenance case.
- Match % truth = `report.json` `fuzzy_match_percent`. Diff tools locate divergence; they don't certify it.
- **Fresh eyes.** This file is deliberately tiny and is **not** a catalogue of techniques or solved
  cases — that omission is on purpose. If a fix isn't here, that means nothing: read the target asm and
  derive it yourself. Every function is matchable; an unsolved one is a spelling not-yet-found, never
  an impossibility.

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

## Integration branch safety
- Retail target objs (`build/GSAE01/obj/...`) are READ-ONLY — never rebuild or delete them. Only the
  source objs (`build/GSAE01/src/...`) are yours to build.
- Normal work lands on the permanent branch `staging`, not directly on `main`. Fetch it from origin
  and rebase local unpushed work onto the fresh remote staging tip before every push; abort and
  re-derive conflicts instead of using `--theirs`.
- A maintainer or bot makes one normal merge commit from `staging` into `main` per UTC day, preserving
  per-change history while making the main Actions build run once for the batch. After publishing
  that merge, fast-forward `staging` to the new main merge commit before reopening it for work; do
  not create dated rollover branches. Reconcile any direct `main` commits into `staging` without
  dropping either side.
- Rebase + `ninja EXIT=0` before each commit; commit only when asked. One owner per `.c`.
- Edit SJIS-bearing files byte-wise (python rb/wb). Never `git stash` in a worktree — use `git checkout -- <file>`.
- **A function rename is NOT byte-neutral and can wreck a unit with a green build.** `config/GSAE01/symbols.txt`
  is build input (`config.split_deps`) — the splitter re-carves the retail objects from it, and objdiff pairs
  functions *and relocation targets* by name, so a source/symbols mismatch scores the function zero and shows a
  diff at every call site in every calling unit. Gate every rename with `python3 tools/pairing_check.py`
  (0 retail-only symbols) plus `unitfuzzy.py` on every unit `pairing_check.py --refs <name>` lists — not just the
  one you edited. See `docs/rename_safety.md`.

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
- **Dummy global-register reservations** — declarations such as
  `register int unused asm("r14")` whose only purpose is to remove a register from MWCC's
  allocator. Recover the real source lifetimes instead and accept the mismatch until then.
- **Pool-reconstruction consts** — `lbl_8XXXXXXX`-named const defs read via `*(f32*)&`; write plain
  literals. This includes the **`const union { f32 f; } lbl_x = { V };` + `lbl_x.f`** disguise (a
  named-`.sdata2` float that blocks folding to force the pool symbol) — banned; write the plain
  literal `V`. (A `union { f32 f; u32 u; }` used via BOTH `.f` and `.u` for a genuine int↔float
  bit-reinterpretation is a different thing and is not this ban.)
A unit that cannot match without one of these stays `NonMatching` (or awaits correction to a
DOL-confirmed TU boundary) — that is the accepted trade. Historical per-hack shapes and costs are
recoverable via `docs/HACK_AUDIT.md`.

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
- DOL-confirmed TU boundaries are structural ground truth. NEVER split a confirmed TU into
  address-suffixed source fragments for per-function cflags, pragma substitutes, match percentage,
  or convenience. Merge artificial fragments in retail function order, use one TU-level compiler
  profile, and accept match regressions. Only redraw a boundary when DOL section, pool,
  function-order, or source-tag evidence establishes a different real TU.
- Every confirmed numbered DLL folder is a real slot. NEVER collapse an adjacent slot because its
  functions, descriptor, or data are currently attributed to the wrong source file. Preserve both
  slots and re-audit the misplaced contents against the DOL. One source file defining multiple
  descriptors is not evidence of a multi-descriptor TU without independent DOL support.
- Rehome DLL source one numbered slot at a time. Before moving a source into its canonical folder,
  audit the complete TU, neighbouring text/data boundaries, descriptor ownership, artificial
  fragments, and section-alignment overrides, then build it. NEVER bulk-rehome DLL sources with
  path-only mechanical moves.
- End an object DLL TU with its `ObjectDescriptor` definition. NEVER move the descriptor earlier
  merely to reproduce post-link section order; keep the source structure plausible and leave the
  unit `NonMatching` when reconstructed declaration order exposes a data mismatch.
- `include/main/gamebit_ids.h`: a NEW `GAMEBIT_*` id ALWAYS goes in the unordered (Rena-imported)
  section, inserted in ascending-id order — NEVER interleave it into the chronological/story-ordered
  section at the top, and NEVER split a comment from the entry it describes. An id may be promoted into
  the ordered section ONLY once its story/activation position has been established by directly debugging
  the game in Dolphin.

## A few MWCC facts (high-frequency only — NOT a map; derive everything else fresh)
- Compare opcode tracks operand width/sign **when it feeds a branch**: `u16`/unsigned → `cmplwi`, `int`/`long` → `cmpwi`. Type the local/field to the field width. (Inert against a runtime `int` operand.)
- Single-bit clear: write `x &= ~0x80` (→ `rlwinm`), not `x &= 0xff7f` (→ `andi`).
- `u8` not `char` for a byte loaded and stored without arithmetic — drops a spurious `extsb`.
- **Saved-register homes: three populations, each with its own key** (same law for `r14..r31` and `f14..f31` — the FP band is not a separate rule). **Load class** — a value materialized *into* its home by a load, a computation or a constant — is keyed on **declaration order**, assigned `r31` downward (first-declared → `r31`); its definition order, use order and use count are all inert. **Copy class** — a value copied from a fixed ABI register, i.e. an incoming parameter or a call return — is keyed on **definition (program) order**, and its declaration order is entirely inert. **Copy class takes the TOP `|C|` registers of the band and the load class fills below it**, definition order running upward inside that sub-band (`C,L,C` → `f30,f29,f31`; `C,C,C,L` → `f29,f30,f31,f28`; `C,L,L,L` → `f31,f30,f29,f28`). The older wording "assigned from the bottom of the band upward" describes only the ordering *within* the sub-band and is wrong about *which* sub-band; the two readings coincide in a pure-copy function, which is why it went uncaught. **Third population — a value produced by an inlined helper that returns through a `volatile` stack slot (the project's `extern inline sqrtf` is the big one)**: declaration order is **inert**, and it is keyed on **assignment order, top-down** (first-assigned takes the highest register). It is neither of the other two, and a declaration sweep over a `sqrtf`-heavy function is therefore turning a provably dead knob — reorder the *assignments*. Probes: 24 decl permutations of four load-class locals give 24 distinct outcomes, the same 24 over four call results give **one**; `L,S,L,S` with the decls reversed swaps the two load homes and leaves both `sqrtf` homes pinned. The populations stay independently steerable when mixed, but their placement is **not** a concatenation of contiguous sub-bands once all three are present — there is no closed-form predictor yet, so measure. A value with **no named local behind it** (a compiler temp, a spill reload, an array base) is in none of them and is not reachable by any ordering knob. **Naming it does NOT move it** — measured on `expgfxGetSlot` and `gameTextInitBoxTextures`, every spelling that preserves the instruction stream is byte-identical, because MWCC coalesces the named local straight back into the same anonymous web. Only changing *where the value is materialized* moves a home, and that is a stream change you must independently want. So a nameless value sitting in the saved band is a **symptom**, not the defect — look for what actually displaced it (usually a base materialized through `r0`, or a copy-class direction flip). Sweep with `tools/permsweep.py` (gates on bytes via `tools/fnbytes.py` — never on tool silence). **Declaration order and assignment order are two INDEPENDENT knobs — split them when a diff is register-numbering *and* emission-order together:** numbering follows declaration, materialization follows assignment, so `f32 b; f32 a = mem; b = K;` gives `a`/`b` the numbering of the declared order and the load order of the assigned order. Neither plain declaration sequence reaches it.
- **The band model is EXACT up to width 4 and then falls off a cliff — screen before you sweep.** Scoring the
  load-class rule above (non-copy saved regs = one declaration-keyed population filling `r31`/`f31` downward) over
  6,288 SFA retail functions, by total saved regs in the band: **GPR 97.7% at 2, 99.3% at 3, 98.8% at 4, then 1.4%
  at 5 and 0.1% at 6+.** It is not a decay, it is a cliff. FP is far weaker at every width (45.5 / 36.8 / 19.3 /
  14.9 / 5.1%) — consistent with the third (`sqrtf`, assignment-keyed) population being common in FP-heavy code, so
  trust the probe result over the rule there. The top-down direction itself is overwhelming where it applies:
  among values first written by a *computation* the down:up ratio is 167:1 / 139:1 / 199:1 at widths 2/3/4.
  Consequence: at >=5 there is no total order to fit and declaration sweeps are provably flat — four exhaustive
  sweeps (720/225/144/121 candidates) returned zero movement, every one a wide-band function. **Narrow band means
  the assignment is PREDICTABLE, not STEERABLE**: a 120-permutation sweep of `playerUpdate` (3 saved GPRs, the 99.3%
  regime) was also completely flat, so use the width screen to find *shape* defects, not to plan register moves.
  `python3 tools/bandscreen.py --struct-only` ranks the frontier by band width and by whether the mnemonic stream
  (not just the operands) differs; see `docs/band_width_worklist.md`.
  **Why the cliff exists** (~1400 synthetic probes): the saved band is a **rotation of one fixed cyclic order**
  `(param, L_n..L_1, pool)`, and the rotation offset is a **whole-function pressure counter that saturates at 2** —
  it counts *every* value the allocator sees, including statements needing no saved register at all, which is why a
  one-instruction change anywhere can re-colour the whole band far away. Declaration order permutes values *within*
  the shape but **can never change the rotation**, so at width >=5 with an identical stream every ordering knob is
  provably flat — route to the TU-split/`mw_version` lane instead of sweeping. Inert for the same reason: dead or
  unused locals, the number of source locals backing a split web, and use counts. GPR and FP bands have independent
  counters. **One move the usual sweeps miss:** a block-scoped local is exactly equivalent to ranking it LAST in the
  enclosing declaration list, so *hoisting* a block-scoped local to function scope (or pushing a function-scope one
  into its innermost block) reaches orderings no permutation of the top-level list can express — worth trying at
  width <=4.
- **A same-length register permutation in the SCRATCH band (`r3..r12`) is a per-TU FLAG signature, not an allocator wall.** Copy/constant propagation reorders the values the allocator sees, permuting scratch homes with the instruction stream held identical — a 10-line probe flips `r4`/`r5` on nothing but `-opt nopropagation`. Probe it **per function** with `tools/fn_flag_probe.py <unit>`; conflicting profiles may show that the current unit merges multiple real TUs, but only DOL evidence may justify correcting that boundary. Never split a DOL-confirmed TU to isolate a flag profile.
- `f32 fn(f32)`, not `double fn(double)`, for single-precision helpers — avoids an `fmul`+`frsp`.
- A single-bit flag written as a C bitfield (`u8 x:1`) compiles to `li; rlwimi`, not a manual `|= mask`.
- FP compare feeding a branch → write the plain operator (`a >= b` → `fcmpo`+branch). A stored/returned float-bool uses a different form.
- Reordering a callee's parameter list is **register-neutral** (the ABI assigns registers by type, not declared order) — use it to match the target's prologue-save / caller arg-emission order.
- Distrust raw derefs/casts — the original was almost always a struct/union/typed array. Try `arr[i].field`, a bitfield/union overlay, or a typed pointer first; it often fixes addressing and coloring, not just readability.
