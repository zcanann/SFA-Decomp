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

- `python3 tools/drift_audit.py` — rank every unit by Ghidra v1.0/v1.1 drift
  score. Drifted units (src `FUN_xxx` whose addresses don't align with the
  v1.0 `.s`) cannot be matched per-function until restructured. Add
  `--only-drifted`, `--min-stubs N`, `--csv`, or a unit substring for detail
  mode.
- `python3 tools/stub_queue.py` — ranked queue of undecompiled functions
  sorted by quick-win likelihood (small size × tractability bonus for units
  that already have other matches). Add `--max-size 200`, `--aligned-only`,
  `--unit <name>`, `--csv` to filter.
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

1. **Triage**: `tools/drift_audit.py --only-drifted` and
   `tools/stub_queue.py --aligned-only --max-size 400` to find work. Bias
   toward aligned units (clean per-fn wins) and small stubs first.
2. **Pick a unit at 0-30% match** (or a single stub from `stub_queue`).
3. **Verify alignment**: if the unit's drift score is non-zero, plan to
   apply the add-new-function or restructure pattern (see CLAUDE.md) BEFORE
   trying to byte-match.
4. **Read source + asm side-by-side**: `src/<path>.c` and
   `build/GSAE01/asm/<path>.s`.
5. **Diff one function**: `function_objdump.py --diff` to see the specific
   instruction-level deltas.
6. **Apply ONE recipe at a time** from CLAUDE.md (peephole pragma, asm{}
   workaround, source-form micro-tweaks, etc.). Rebuild. Recheck.
7. **If % drops, revert immediately** — `git checkout -- <file>`.
8. **Commit each meaningful gain** (>1% fuzzy, a function newly matched, or
   a structural fix that aligns the function set). See commit protocol below.
9. **Budgets**: 20 min hard limit per function. "Task complete" ≠ 100%
   match — "materially better with multiple gains" is enough. Move on rather
   than overfit one function.

## Commit & push protocol (CRITICAL — shared remote main)

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

Use `TeamCreate` to make `sfa-decomp-hunt`, then `TaskCreate` to seed
6-10 tasks (mix of small / medium / big units; bias small for throughput).
Spawn 3-5 hunter agents in parallel with `Agent(team_name=..., name=...,
run_in_background=true)`. Each agent gets its own worktree per the setup
above. Hunt for functions that have not been decompiled at all — small units
with high stub counts are usually highest throughput. Don't shy away from
big or complex functions, but budget per-function and move on if stuck.

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
7. **`register T name;` declaration order** matches register allocation
   order (first declared → r0, second → r3, ...).
8. **Inline `asm { ... }` block** with `register` locals — last-resort but
   reliable for forcing `rlwimi` / `li+and` / `cmplwi`.

When a `.c` is drifted (Ghidra-imported from v1.1, src `FUN_xxx` don't match
v1.0 `.s`):

- **Add the asm symbol as a NEW function** in the .c. Dead `FUN_xxx` float
  harmlessly; the linker matches by name. Refs: `aedc9605`, `fa042933`,
  `43ab8f56`.
- **Full source-set restructure** for deeper drift: use
  `realign_skeleton.py --merge` to bootstrap, then fill bodies.

Reference commits to study before starting: `2e20e326`, `01400901`,
`a42bb90b` (asm{}); `aedc9605`, `fa042933`, `43ab8f56` (add-new-function);
`dbbc5ba9` (full restructure); `77438a6f` (clamp form); `6863ffe7` (u8).

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
