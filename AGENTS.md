# AGENTS_NEW.md - Agent Runbook (SFA-Decomp)

This is the concise runbook for automated contributions to **SFA-Decomp**.

Goal: maximize real progress by improving C/C++ source, linkage, headers, types, data layout, and adjacent code where needed, then rebuilding, diffing, and submitting clean PRs only when the result is both better and plausible.

## Source Of Truth
- **Objdiff is the source of truth** for progress.
- **Ghidra is a guide**, mainly for addresses, sizes, and rough function shape.
- Function names from shipped Metrowerks symbols are usually correct. Parameters from Ghidra may not be.

Useful references:
- Ghidra decomp: `resources/ghidra-decomp-1-31-2026/`
- PAL map: `orig/GCCP01/game.MAP`
- EN map: `orig/GCCE01/game.MAP`
- Symbol extractor: `python3 tools/extract_symbols.py <object>.o`

When updating functions, keep the version header block:

```c
/*
 * --INFO--
 * PAL Address: 0x80001234
 * PAL Size: 128b
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
```

## Preconditions
Skip setup unless the repo is not already prepared.

```sh
python3 configure.py --version GCCP01
ninja
python3 tools/download_tool.py objdiff-cli tools/objdiff-cli --tag v3.6.1
tools/objdiff-cli --version
```

PAL (`GCCP01`) is the only active target.

## Contribution Loop

### 1. Select a target
```sh
python3 tools/agent_select_target.py
```

### 2. Branch from clean `main`
```sh
git checkout main
git pull origin main
git checkout -b pr/<unit>/$(date -u +%s)
```

If local changes exist from a prior run, assume they should be discarded unless told otherwise.

### 3. Work the target, then work outward
Start from the selected mismatched function or data, but do not stay artificially narrow if the real blocker is adjacent.

Agents are explicitly allowed, and expected, to go on a **crusade around the target** when it helps matching:
- fix headers, forward declarations, and includes
- correct function signatures and class layouts
- replace `extern` hacks with real definitions and linkage where practical
- fix signedness, typedefs, enums, constants, and ABI-relevant types
- replace hard-coded offsets with real member variables and member access
- repair nearby structs, globals, constructors, vtables, and helper functions
- update `config/GCCP01/symbols.txt` when symbol naming is the real issue
- adjust `configure.py` flags when flags are the blocker, not the source
- reference .MAP files for trying to figure out how sdata, bss, etc sections may be set up

Do not optimize only for the named symbol if the surrounding code is what prevents a real match.

### 4. Build
```sh
ninja
```

### 5. Diff
```sh
build/tools/objdiff-cli diff -p . -u <unit> -o - <symbol> > diff_result.json
```

### 6. Evaluate net progress
Treat these as first-class wins:
- code match
- data match
- linkage progress
- cleaner, more correct declarations that unblock future matching

Small local regressions are acceptable if they unlock larger real gains nearby.

### 7. Create a PR only if both are true
**A) Real net progress**
- objdiff or build output improved in code, data, or linkage
- gains are real, not formatting, renames, or temporary hacks

**B) Plausible original source**
- the code looks like something the FFCC developers could have written
- types, fields, control flow, and linkage are more coherent than before

### 8. Submit
```sh
git commit -m "Descriptive message"
git push -u origin HEAD
gh pr create --title "..." --body "..."
```

PRs should summarize:
- what changed
- which units or symbols improved
- before/after evidence
- why the result is plausible source, not compiler coaxing

## Critical Rules
- Prefer defining & linking things over using `extern` as a crutch.
- If its not clear where something is defined, try using the .MAP files.
- Do not manually force sections like `__declspec(section ".ctors")`.
- Do not manually write dtor/ctor/sinit functions that are likley generated.
- Do not hardcode addresses or use fake `lbl_` / `fn_` names to chase output.
- Use real member access instead of pointer-offset tricks.
- Keep code clean: no junk comments, no analysis debris, no commented-out experiments.
- Notes belong in the agent workspace, not the project tree.
- Branch from `main`, never from another PR branch.
- When in doubt, bias towards what the actual source code looked like.

## Operating Principle
Do not treat the selected symbol as a tiny sandbox. Treat it as the center of a dependency cluster.

If matching the target requires fixing adjacent linkage, includes, headers, structs, globals, constructors, or helper functions, do that work. Recovering coherent original source is the goal, not narrowly editing one function while leaving the surrounding code obviously wrong.

## Minimal Workflow
1. `python3 tools/agent_select_target.py`
2. Branch from clean `main`
3. Fix the target and any adjacent blockers
4. `ninja`
5. `build/tools/objdiff-cli diff -p . -u <unit> -o - <symbol>`
6. If net progress is real and plausible, commit, push, and open a PR
