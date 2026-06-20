# Handover: crack fn_801B3DE4 via dynamic RE of mwcceppc (x86 Ubuntu)

You are continuing work that was blocked on an arm64 Mac. **Goal: 100% match
`fn_801B3DE4` using the compiler reverse-engineering technique** (no inline asm — forbidden).
On x86 Ubuntu the path that was blocked for me — live-debugging the compiler — is open to you.

## TL;DR of where it stands
- `fn_801B3DE4` (in `src/main/dll/DIM/dll_01CA_dimexplosion.c`, GC/2.0, `-O4,p`) is at **98.04%**.
- The **only** divergence is ONE instruction: the target has `mr r29, r31` (a copy of
  `state+off` into a second callee-saved reg used for the `0x14` field); MWCC's O4
  value-numbering folds it, so my build reuses `r31`.
- Saved-reg layout is otherwise correct: `state→r28, off→r30, e→r31`.
- ~18 clean-C spellings + all `optimization_level`s + CSE/propagation pragmas were tried;
  none reproduce the `mr`. Full list in `docs/mwcc_re/fn_801B3DE4_partial.md`.
- The fold lives in MWCC's **`ValueNumbering.c`**, mapped to `mwcceppc.exe` @ **`0x509010`**.

## Your job
Use a debugger on the *running compiler* to learn the exact condition under which
ValueNumbering refuses to substitute one `state+off` web for the other — then find a clean-C
source spelling that hits it. The arm64 host couldn't breakpoint the PE's VAs (wibo runs the
32-bit PE via i386 LDT segments under Rosetta). On x86 Ubuntu, run the compiler the normal way
and gdb can break at the flat VA directly.

## Environment setup
- Compiler binary: `build/compilers/GC/2.0/mwcceppc.exe` (PE32, Version 2.4.7 build 92).
- Runner: `build/tools/wibo` (download an x86_64 Linux build from
  `github.com/decompals/wibo` if the checked-in one is Mach-O). On x86 Linux you can ALSO
  try `qemu-i386` or `wine` — whichever lets gdb see the PE at its image base `0x400000`.
- Build a single unit: `ninja build/GSAE01/src/main/dll/DIM/dll_01CA_dimexplosion.o`
- Exact compile command: `ninja -t commands build/GSAE01/src/main/dll/DIM/dll_01CA_dimexplosion.o`
- Match %: `ninja build/GSAE01/report.json` then read `fuzzy_match_percent` for `fn_801B3DE4`.
  (If `report.json` won't regenerate: `rm build/GSAE01/config.json && ninja
  build/GSAE01/config.json` to re-split the target objects, which it needs.)

## RE tooling already built (in this repo, untracked)
- `tools/mwcc_assert_map.py <mwcceppc.exe>` — maps compiler functions to source files via
  embedded `assert(file,line)` strings (needs `pip install pefile capstone`).
  Output already generated: `docs/mwcc_re/assert_map_GC2.0.txt`.
- Key addresses (image base 0x400000, no ASLR under wibo):
  - `ValueNumbering.c`  @ `0x509010`  (the fold — primary target)
  - `Coloring.c`        @ `0x508680`, `0x508900`, `0x508c10` (register allocator/coalescer)
  - `InterferenceGraph.c` @ `0x57b680`, `0x57bad0`
  - `SpillCode.c`       @ `0x57c290`+   `Scheduler.c` @ `0x508100`
  - `IroCSE.c`          @ `0x46a360`+ (the other place a copy can be eliminated)

## Concrete first steps
1. Confirm you can break at the VA. Run the compile under gdb:
   `gdb --args build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe <flags> -c <src> -o <dir>`
   then `break *0x509010`, `run`. If it hits, you're in business. If wibo maps the PE
   elsewhere, find the base: `info proc mappings` and look for the ~2MB r-x region, or search
   for the prologue bytes of 0x509010: `53 56 57 55 83 ec 20 8b 4c 24 34`. Real BP =
   mapped_base + (0x509010 - 0x400000).
2. With a breakpoint in ValueNumbering, compile the unit and watch how the two `state+off`
   expressions get the same value number. Identify the predicate that lets it substitute the
   second use. Diff that against a sibling function where MWCC *does* keep two regs for one
   value (rare — only 3 base-duplication sites exist game-wide; all are walker loops).
3. Translate the predicate into a source construct and verify with the report. The diff you're
   chasing is purely: produce `mr r29,r31` + make the five `0x14` accesses use `r29`.

## Ground-truth target asm
`build/GSAE01/asm/main/dll/DIM/dll_01CA_dimexplosion.s`, lines 9–200 (`.fn fn_801B3DE4`).
Compare with `build/binutils/powerpc-eabi-objdump -drz --disassemble=fn_801B3DE4
build/GSAE01/src/main/dll/DIM/dll_01CA_dimexplosion.o`.

## Rules
- No inline `asm {}` — ever. The match must come from clean C / pragmas.
- Source of truth for % is `report.json` `fuzzy_match_percent`; force-rebuild the `.o` first.
- The function currently carries `#pragma peephole off` + `#pragma opt_propagation off`.
- Don't regress other functions in the same TU (the file is deliberately untyped — see the
  header comment about #36/#77 coloring coupling).
