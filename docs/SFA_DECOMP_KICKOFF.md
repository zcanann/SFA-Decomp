# SFA-Decomp — Team Kickoff Prompt

Paste this whole document as the kickoff prompt for a multi-agent decomp session.
It assumes the working directory is `/home/jack/code/SFA-Decomp` and the repo is on
branch `main` tracking `origin/main`. Multiple developers (humans + agents) push to
`main` live, so every commit must be rebased before push.

---

You're working on the StarFox Adventures (SFA) decompilation project at
`/home/jack/code/SFA-Decomp`.

- **Target**: EN v1.0 (`GSAE01`).
- **Compiler**: MWCC (likely `GC/1.2.5n`).
- **Read first**: `CLAUDE.md` (matching playbook) and `AGENTS.md` (project runbook
  + Ghidra Drift Playbook section). These are required reading — they document
  the techniques the team has already discovered and will save you from
  reinventing them.

## Per-agent worktree setup (REQUIRED for parallel work)

Each agent gets its own git worktree on its own branch so that builds don't
collide. Pick a `{uniqueid}` per agent (e.g. `alpha`, `bravo`, ...).

```bash
# 1. Worktree on a unique branch tracking origin/main (NOT -b main; main is
#    already checked out elsewhere — that would conflict).
git worktree add /home/jack/code/SFA-Decomp-hunter-{uniqueid} \
    -b hunter-{uniqueid} origin/main

# 2. Symlink orig/ into the worktree (the .iso and sys/ are big and shared).
mkdir -p /home/jack/code/SFA-Decomp-hunter-{uniqueid}/orig/GSAE01
ln -sf /home/jack/code/SFA-Decomp/orig/GSAE01/sys \
    /home/jack/code/SFA-Decomp-hunter-{uniqueid}/orig/GSAE01/sys
ln -sf "/home/jack/code/SFA-Decomp/orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso" \
    "/home/jack/code/SFA-Decomp-hunter-{uniqueid}/orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso"

# 3. cd in and configure (use python3, NOT python).
cd /home/jack/code/SFA-Decomp-hunter-{uniqueid}
python3 configure.py --matching

# 4. Build. Always wrap with timeout 30-60s; CI runs the strict hash target.
timeout 60 ninja

# 5. Regen report if needed (ninja does NOT auto-regen).
rm -f build/GSAE01/report.json && timeout 30 ninja build/GSAE01/report.json
```

## Tooling

### Triage tools (run these FIRST when picking work)

**PRIMARY — find genuinely-untouched work from `report.json`, not stub_queue.**
The single most reliable triage: list the units at **0% matched** (fully
untouched, uncontended) and the barely-started ones. At the last audit there
were **71 fully-untouched (0%) units + 221 at 0–25%** — a huge fresh backlog
that `stub_queue.py`/`drift_audit.py` alone do NOT surface well. Regen the
report first (`rm -f build/GSAE01/report.json && timeout 30 ninja
build/GSAE01/report.json`), then:

```bash
python3 - <<'PY'
import json
def num(x):
    try: return int(x)
    except: return 0
r=json.load(open("build/GSAE01/report.json")); m=r["measures"]; us=r["units"]
print(f"project: {m['fuzzy_match_percent']:.1f}% fuzzy | "
      f"{m['matched_functions']}/{m['total_functions']} fns ({m['matched_functions_percent']:.1f}%) | "
      f"{m['matched_code_percent']:.1f}% bytes")
zero=[(num(u['measures'].get('total_code',0)),num(u['measures'].get('total_functions',0)),u['name'])
      for u in us if (u['measures'].get('matched_code_percent',0) or 0)==0
      and num(u['measures'].get('total_functions',0))>0]
zero.sort(key=lambda x:x[1])           # smallest fn-count first = quickest fresh pools
print(f"{len(zero)} fully-untouched (0%) units (smallest first):")
for tc,tf,n in zero: print(f"  {tf:>2}fn {tc:>6}B  {n}")
PY
```

Pick fresh 0% units to hunt. Good families seen this session: `dll/baddie/*`,
`dll/CAM/*`, `audio/*`, and the many small `dll/dll_*`. **One owner per unit**
(two agents editing the same `.c` ⇒ duplicate defs + rebase collisions).

**Two flavors of 0%-matched unit — only flavor A is high-yield clean-C work:**
- **(A) MISSING-from-src (drift):** the asm has symbols that are NOT defined in
  the `.c`. These are the **add-new-function** wins — add the symbol as a new
  correctly-named function; they routinely hit 90–100% from clean C. *This is
  the productive pool.* (gameplay, sandwormBoss, DIMcannon/DIMlavaball,
  pi_dolphin were all this.)
- **(B) present-but-unmatched:** the function body is ALREADY in the `.c`
  (Ghidra-imported) but compiles to non-matching code. These are
  partial-improvement only and the residuals are usually
  register-allocation/FP-scheduling — i.e. asm-territory we skip. Low yield;
  don't mistake a flavor-B unit for fresh work.

Distinguish them per unit: `comm -23 <(grep -oE '^\s*\.fn \S+' build/GSAE01/asm/<unit>.s | awk '{print $2}' | sort -u) <(grep -oE '\b(fn_[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]*)\s*\(' src/<unit>.c | ...)` — or more simply, open the `.c`: if the 0% functions already have full bodies, it's flavor B (skip); if the asm symbols are absent from the `.c`, it's flavor A (go). External "naming/pragma sweep" commits also leave a unit at 0% while editing it — check `git log -1 --grep=<unit>` and prefer never-touched units to avoid colliding with other contributors.

- `python3 tools/drift_audit.py` — rank every unit by Ghidra v1.0/v1.1 drift
  score. Drifted units (src `FUN_xxx` whose addresses don't align with the
  v1.0 `.s`) cannot be matched per-function until restructured. Add
  `--only-drifted`, `--min-stubs N`, `--csv`, or a unit substring. **CAVEAT:
  its STUBS column is inflated** — it counts dead `FUN_xxx` at drift addresses,
  so real missing-from-src work is fewer than the number suggests. Confirm with
  `grep '\.fn ' build/GSAE01/asm/<unit>.s` vs the symbols present in the `.c`.
- `python3 tools/stub_queue.py` — ranked undecompiled-function queue. **CAVEAT:
  output is STALE** — it flags already-matched functions (and dead `FUN_xxx`)
  as stubs, so it sends you to functions that are already done. Do NOT trust it
  as the "untouched" source; use the report.json 0%-unit query above instead.
- `python3 tools/realign_skeleton.py <unit>` — emit a v1.0-aligned C
  skeleton from the asm function set, ready for filling. Add `--merge` to
  keep the existing src under `#if 0` for body mining, `--inplace` to
  overwrite the src file.

### Diff/inspection

- `python3 tools/function_objdump.py --diff <unit> <symbol>` — per-function
  target/current diff. Works on Linux (falls back from `.exe`).
- objdump path: `build/binutils/powerpc-eabi-objdump`
- Per-unit asm output: `build/GSAE01/asm/<path>.s`
- Compiled object: `build/GSAE01/src/<path>.o`
- `objdiff-cli` is INTERACTIVE only — don't try to drive it non-interactively.

## Workflow

0. **Targeting reality (read once).** The project sits around ~34% fuzzy /
   57% of functions / ~18% of *bytes* matched. The function%≫byte% gap means
   the unmatched code is dominated by **large FP/GX/matrix/render/physics
   functions** — these are asm-territory and, under the no-asm Prime Directive,
   stay partial/untouched (skip them). The clean-C wins live in the **many
   SMALL functions** (init/update/free/dispatch/logic) inside fresh 0% units.
   So target small functions in untouched units for fuzzy%/function-count
   gains; do not chase the byte-heavy giants.
1. **Triage**: run the report.json 0%-unit query above to get fresh untouched
   units; pick one no other agent owns. (Use `drift_audit.py <unit>` to gauge
   drift, but remember its stub count is inflated and stub_queue is stale.)
2. **Pick a fresh 0% unit** (or a 0–25% unit) and claim it as sole owner.
   Bias to units with several small functions for throughput.
3. **Verify alignment**: 0% units are typically drift/missing-from-src, so
   plan the **add-new-function** pattern (add the asm symbol as a NEW
   correctly-named function; dead `FUN_xxx` float harmlessly) — see CLAUDE.md
   Drift handling. Restructure BEFORE trying to byte-match.
4. **Read source + asm side-by-side**: `src/<path>.c` and
   `build/GSAE01/asm/<path>.s`.
5. **Diff one function**: `function_objdump.py --diff` to see the specific
   instruction-level deltas.
6. **Apply ONE clean-C recipe at a time** from CLAUDE.md (peephole pragma,
   bitfield→rlwimi #12, case-label ordering #13, source-form micro-tweaks).
   Rebuild. Recheck. **NO inline asm** — leave the residual as a partial.
7. **Build hygiene before every push**: `timeout 60 ninja; echo EXIT=$?` must
   be `EXIT=0`. Warnings (`'extraout_f1'/'in_rN' not initialized` Ghidra
   phantoms) and the strict-hash/checksum MATCH target are NOT build breaks —
   only `error:`/`FAILED:` with non-zero exit is. If % drops, revert
   immediately — `git checkout -- <file>`. Clean Ghidra phantoms out of bodies.
8. **Commit each meaningful gain** (>1% fuzzy, a function newly matched, or
   a structural fix that aligns the function set). See commit protocol below.
9. **Budgets**: 20 min hard limit per function. "Task complete" ≠ 100%
   match — "materially better with multiple gains" is enough. Move on rather
   than overfit one function. A clean 85–99% partial beats an asm-forced 100%.

## Commit & push protocol (CRITICAL — shared remote main)

**ALWAYS commit and push directly to `main` after finishing EVERY function** —
do not batch, and do not sit on local commits. Other agents (and humans) push
to `main` live, so they need to see your work immediately to avoid editing the
same code and colliding. One function matched/improved = one commit = one push.

After EACH match gain:

```bash
git add -A
git commit -m "Recover <unit>: <function or change>"
git fetch origin main
git rebase origin/main
git push origin HEAD:main
# If push rejected: git fetch origin main && git rebase origin/main && retry.
```

- **NEVER** push `--force` to main.
- **NEVER** add `Co-Authored-By: Claude` to commits.
- **NEVER** bypass git hooks (`--no-verify`).
- If you hit a rebase conflict in a file you don't own, abort with
  `git rebase --abort`, re-pull, and skip that file — message the team lead.

## Spawning a team

Use `TeamCreate` to make `sfa-decomp-hunt`, then `TaskCreate` to seed tasks
**from the report.json 0%-unit list** (one fresh untouched unit/family per
task — `dll/baddie/*`, `dll/CAM/*`, `audio/*`, small `dll_*`). Spawn 3-5
hunter agents in parallel with `Agent(team_name=..., name=..., model="opus",
run_in_background=true)`, each on its own worktree per the setup above.
**Run every hunter on Opus, not Sonnet** — pass `model="opus"` on every
`Agent` spawn (Sonnet is materially weaker at this matching work).

Coordination rules (learned the hard way — these prevent collisions and false
alarms):
- **One owner per unit / one agent per `.c`.** Two agents recovering the same
  unit produce duplicate definitions and rebase conflicts. Assign distinct
  units; require **confirm-before-commit** when a hunter picks a new unit so
  the lead can lock the lane before any push.
- **Seed from 0% units, not stub_queue** (stale). Keep ≥3 fresh unowned units
  queued; reassign hunters to new 0% units as they exhaust a pool.
- **Long-context hunters should retire** at a clean point and hand off a map of
  remaining candidates; replace with a fresh-context agent to maintain the
  roster. (Right team size is ~4–5; more just causes lane contention.)
- **Verify build reports before alarming.** "pi_dolphin is RED" type reports
  were repeatedly the checksum-match target (always fails until 100%) or MWCC
  phantom-var warnings — not real breaks. Check `ninja` exit code first.

Commit and push regularly to `main`. You may need to rebase often as other
people are also working on this project live.

## Quick reference: matching recipes

Try in order when a function is already 80-95%:

1. **`#pragma peephole off`** at the top of the function or above a hot
   block. Single highest-impact one-liner. (See `CLAUDE.md`.)
2. **`& ~constant`** instead of `& 0xFF7F`-style literal → emits `rlwinm`.
3. **`*(void **)ptr != NULL`** instead of `*(int *)ptr != 0` → emits
   `cmplwi`.
4. **`if (v > N) v = N; return v;`** for clamp (emits `blelr`).
5. **Declare `u8`/`u16`** not `char`/`int` to kill spurious `extsh`.
6. **Tempo CSE**: lift repeated load to a local before multiple stores.
7. **Model a single-bit flag as a C bitfield** (`u8 x:1;` then `s->x = 1;`) to
   get target's `li; rlwimi` from clean C (CLAUDE.md #12). Read the bit
   position off the target `rlwimi rX,rS,sh,mb,me`.
8. **Reorder C `case` labels to match target block-address order** for
   compare-chain switches — bodies emit in source order (CLAUDE.md #13).
9. **Local declaration order controls register coloring** (clean C, CLAUDE.md
   #16) — reorder locals to fix a register-permutation residual.
10. **NO inline `asm`** under the current Prime Directive. If a residual only
    yields to asm, leave it as a clean partial and move on.

When a `.c` is drifted (Ghidra-imported from v1.1, src `FUN_xxx` don't match
v1.0 `.s`):

- **Add the asm symbol as a NEW function** in the .c. Dead `FUN_xxx` float
  harmlessly; the linker matches by name. Refs: `aedc9605`, `fa042933`,
  `43ab8f56`.
- **Full source-set restructure** for deeper drift: use
  `realign_skeleton.py --merge` to bootstrap, then fill bodies.

Reference commits to study before starting: `aedc9605`, `fa042933`,
`43ab8f56` (add-new-function — the core drift workflow); `dbbc5ba9` (full
restructure); `a3a86c446`, `34ee540c0` (bitfield→`rlwimi` clean C);
`61dd19936` (case-label ordering); `77438a6f` (clamp form); `6863ffe7` (u8).
(The older `asm{}` reference commits are deprecated under the current no-asm
Prime Directive — don't study or imitate them.)

---

## Known systemic blockers (don't burn cycles here)

- **Spawner/vtable-dispatch units** (`foodbag`, `dim_partfx`, `df_partfx`):
  many `func03`-style functions take a ~30-field stack struct as input.
  Without the struct definition for the spawner's input, no source form
  matches. Needs struct-recovery tooling before per-function matching is
  tractable.
- **Anonymous sdata2 constants** (`@23`, `@32`, `@72`): cap functions at
  ~98% unless we own the file's sdata2 split.
- **Build artifact caching** (sccache/ccache around MWCC) would speed
  worktree onboarding from ~60s to ~10s but is invasive — not yet wired up.
