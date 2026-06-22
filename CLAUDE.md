# SFA-Decomp

Decompilation of Star Fox Adventures (GameCube): recover plausible original C that byte-matches the
retail binary. Main lib compiled with MWCC GC/2.0; audio/MSL with 1.2.5n.

## Goal & rules
- Recover the **plausible 2002 C** a Rare dev would have written. Inline `asm{}` is banned — the one
  exception is paired-single `psq_l`/`psq_st` (MWCC has no intrinsic). A clean-C 90% beats an asm 100%.
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
A fix derived from a real matched example beats any written recipe, and the corpus only grows as the
project matches more.

## Build & verify
- Rebuild one unit + the report:
  `rm build/GSAE01/src/main/<path>.o && ninja build/GSAE01/src/main/<path>.o && ninja build/GSAE01/report.json`
- `timeout 60 ninja; echo EXIT=$?` — must be `EXIT=0` before any commit.
- Paired-single disasm: `build/binutils/powerpc-eabi-objdump -M gekko -drz` (stock objdump mis-decodes PS as VSX).
- Tools are in `tools/` — start with `function_objdump.py <unit> <symbol>` (full target asm) and `ndiff.py`.

## Don't break `main`
- Retail target objs (`build/GSAE01/obj/...`) are READ-ONLY — never rebuild or delete them. Only the
  source objs (`build/GSAE01/src/...`) are yours to build.
- Branch off main; rebase + `ninja EXIT=0` before each commit; commit only when asked. One owner per `.c`.
- Edit SJIS-bearing files byte-wise (python rb/wb). Never `git stash` in a worktree — use `git checkout -- <file>`.

## A few MWCC facts (high-frequency only — NOT a map; derive everything else fresh)
- Compare opcode tracks operand width/sign **when it feeds a branch**: `u16`/unsigned → `cmplwi`, `int`/`long` → `cmpwi`. Type the local/field to the field width. (Inert against a runtime `int` operand.)
- Single-bit clear: write `x &= ~0x80` (→ `rlwinm`), not `x &= 0xff7f` (→ `andi`).
- `u8` not `char` for a byte loaded and stored without arithmetic — drops a spurious `extsb`.
- Local **declaration order** sets saved-register homes (first-declared top-loaded value → highest reg). Reorder decls to swap registers.
- `#pragma peephole off` / `scheduling off` (paired with `reset`) around a fn unfuses `extsb.`/`rlwinm.` dot-merges and fixes call/FP scheduling — only in `-O4,p` units, never the noopt/audio units.
- `f32 fn(f32)`, not `double fn(double)`, for single-precision helpers — avoids an `fmul`+`frsp`.
- A single-bit flag written as a C bitfield (`u8 x:1`) compiles to `li; rlwimi`, not a manual `|= mask`.
- FP compare feeding a branch → write the plain operator (`a >= b` → `fcmpo`+branch). A stored/returned float-bool uses a different form.
- Reordering a callee's parameter list is **register-neutral** (the ABI assigns registers by type, not declared order) — use it to match the target's prologue-save / caller arg-emission order.
- Distrust raw derefs/casts — the original was almost always a struct/union/typed array. Try `arr[i].field`, a bitfield/union overlay, or a typed pointer first; it often fixes addressing and coloring, not just readability.
