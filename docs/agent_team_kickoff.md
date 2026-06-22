# Agent-Team Kickoff — SFA-Decomp Matching

Paste the **KICKOFF PROMPT** below to the lead agent (Claude Code) to spin up the team fast.
The role definitions and discipline that made the run productive are baked in so the lead
inherits them immediately. The **validator** role is the standout — keep it.

---

## KICKOFF PROMPT (paste this verbatim, fill the two [bracketed] bits)

Start an agent **team** to improve the match % of decompiled functions in `src/main/dll/` (and game
code generally). Use the **agent-teams feature + SendMessage** to manage members — do **NOT** launch
fire-and-forget background subagents. Give **each member its own git worktree**.

**BEFORE launching:** thoroughly clean `CLAUDE.md` (the playbook) of ALL defeatism/pessimism —
strip every "banked / exhausted / capped / impossible / not reachable / as-good-as-it-gets /
do-not-retry / tried-and-failed / INERT-verdict" phrasing. It makes agents skip functions without
trying, and it has cost real solutions every time. Reframe every open residual as a **live target
with a defined next lever**. Commit + push that cleanup FIRST so all members inherit it.

**Team = 2 HUNTERS + 1 VALIDATOR:**

- **HUNTERS (×2)** — each owns **1 HARD unit** for a deep dive. Grind functions **in-tree**: dump and
  read the WHOLE target asm first (`function_objdump.py <unit> <symbol>`), note each `bl`'s real arg
  shape + field widths, THEN diff. Apply playbook levers; verify against `report.json`
  `fuzzy_match_percent` (the ONLY source of truth — force-rebuild the unit's src `.o` first).
  **Grind hard (10–20 builds/fn) before deferring** — a regression in one direction is a clue you can
  fix from another, not a wall. When genuinely stuck after real effort, route to the validator with the
  **EXACT asm shape** (symbol + target-vs-ours diff + which instruction/reg differs).

- **VALIDATOR (×1) — the highest-value role; keep this flow.** Does NOT chase matches. Two jobs:
  1. **Empirically validate + DERIVE the playbook's levers in ISOLATION.** Write C exactly as the
     playbook describes, compile with the real `mwcceppc.exe` flags, confirm it produces the expected
     asm — and push each entry's boundaries. Treat recipes as HYPOTHESES to prove, not facts.
  2. **Oracle-or-derive for stuck hunters.** Given a stuck fn's exact asm shape:
     (a) **ORACLE** — grep matched `.o`s (`build/GSAE01/obj/**`) or the MP4 corpus for that asm shape,
     read the C that produced it; (b) **DERIVE** — if no oracle exists, INVENT the lever from first
     principles via *add-ingredients* probing (add one structural ingredient at a time to a minimal TU
     until the target behavior fires, then name the exact trigger). Hand the **producing-C** back; the
     hunter verifies it IN-TREE.

- **RE-VALIDATION PASS (assign to the validator, or a 4th "disprover" agent):** have a fresh, skeptical
  agent **re-check existing matched work + the playbook's claims** — probe each load-bearing recipe,
  disprove what's wrong, sharpen what's vague, and confirm "matched" fns are actually faithful (not asm
  hacks / placeholders). Log disproofs; the lead integrates only what survives.

**Core discipline — this is what made it work; enforce it:**
- **No defeatism, ever.** Every function has plausible original 2002-Rare C; the playbook is NOT
  exhaustive (a missing lever is undiscovered, not impossible). Reframe "can't" → "lever not found
  yet." "Emergent / pressure-gated / not isolable" is a banned cop-out — reverse-engineer the concrete
  trigger. Inline `asm{}` is forbidden EXCEPT where the **owner explicitly authorizes** a specific case
  (e.g. paired-single `psq_l`, which matches the codebase's own convention).
- **Verify against the bytes.** `--diff`/`ndiff`/`rotmap` LOCATE divergence, never certify (they mask
  reorders/fusion; rotmap invents phantom "structural" regions on misalignment). Read the FULL fn, the
  CORRECT loop's block (in a multi-loop fn, confirm you're reading the right `addi` block), and the
  EXACT store/reg — never a loose grep (a bare `stw r0`/`li r0` matches the prologue mflr save and
  produces false reads). To prove a shape UNachievable, scan **RETAIL** objs, never our SRC objs (src
  lacking the construct is the bug, self-confirming — if retail has it, it's achievable by definition).
- **Isolation ≠ in-tree.** The validator's isolation derives are HYPOTHESES. Integrate a lever into the
  playbook as SOLVED only after a hunter confirms it IN-TREE with the EXACT regs. Hold integration
  pending that gate — it repeatedly caught convincing-but-wrong levers (oracle + A/B + an elegant
  mechanism, half of which didn't survive a fresh probe) BEFORE they shipped to the hunters.
- **Lead curates the playbook skeptically.** Independently reproduce a disproof before editing.
  Integrate only PROVEN content. **No confirmation noise** — don't annotate things that already work;
  change an entry only on a genuine disproof or a new finding. **Self-correct your own integrations**
  the moment a hunter's in-tree result contradicts them. Write every entry with ZERO pessimism.
- **Hygiene:** rebase `origin/main` + confirm `ninja` EXIT=0 before every commit; commit + push
  FREQUENTLY (other contributors are active — surface conflicts early); one owner per `.c` (concurrent
  edits → duplicate defs); edit SJIS-bearing files byte-wise. NEVER delete/rebuild the RETAIL target
  (`build/GSAE01/obj/...`); the buildable src obj is `build/GSAE01/src/...`.

**Starting units:** [pick 2–3 hard dll/game units below 99%, 1 per hunter — the remaining units are all
HARD; give each hunter ONE for a deep dive]. The validator starts on the re-validation pass + stands by
for stuck-fn routing.

---

## Why this works (notes for the lead)

**The routing loop is the engine.** Hunter grinds in-tree → hits a precise wall (names the exact
asm/reg) → validator oracle-or-derives the producing-C in isolation → hunter applies + verifies in-tree
→ lead integrates the lever (only after in-tree confirmation). This converts every "stuck" into either
a confirmed lever or a precisely-characterized live target. Hunters and validator check *each other*
against the bytes — verify-don't-assume becomes peer-to-peer, not just top-down.

**The validator's superpower is turning "I'm stuck" into a named mechanism.** Over a run it will: derive
levers no recipe covered (invented from first principles when no oracle exists), build a working model
of the allocator, unify several separate puzzles into one nut, and — crucially — make honest
self-corrections (it will misread a register or over-claim an A/B; the value is that it *retracts and
sharpens* rather than defends). Budget for that: a wrong-but-convincing derive caught at the in-tree
gate is the system working, not failing.

**The lead's job is curation + skepticism, not grinding.** Hold the line on: no defeatism in the
playbook, no confirmation noise, reproduce disproofs before integrating, and the isolation→in-tree
gate. When a hunter or validator says "build-domain / unreachable / capped," push back with the
specific untried form — that verdict has been wrong nearly every time it came up.

**Recurring frontier classes** (so you recognize them fast): creation-order coloring (#108/#136 — source
declaration/creation order sets within-class register homes; relocate the creating expression), the
conversion-bias FP register (#148 — conversion source-position; inert when the result is stored+re-read),
value-0 / const-keep (O4 graph-coloring keeps a const in a saved reg, O2 re-materializes), and the
genuinely-hard pressure-driven free-reg picks (context-bound, not isolable — fresh-eyes/oracle targets).
Structural/drift/extern-type/width bugs are higher-yield-per-fn but get mined out early; after that the
work is the allocator/conversion coloring frontier, plus a small owner-domain pile (paired-single
inline-asm, foreign-compiler objects, symbols.txt sizes).

**Scope notes:** `report.json fuzzy_match_percent` is the gate, NOT byte-identity (renames/struct
consolidation are fine if % holds). When a fn's only diff is an `@NNN`-vs-named pool/reloc, that's
usually score-neutral (#70) — don't chase it. A lever that DROPS the headline % but surfaces a needed
structural feature (an extra saved reg, a surviving copy) is good news — the feature is reachable;
find the clean source form that produces it without the collateral cost.
