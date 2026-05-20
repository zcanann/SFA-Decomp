# SFA-Decomp Matching Playbook (MWCC 1.2.5n, EN v1.0)

Short field-tested reference for getting MWCC-compiled C to match the target
binary. Read in 60 seconds, apply in the order they appear; the later sections
are more invasive.

## Prime directive: recover plausible C, not byte-perfect asm

The goal of this project is plausible original source. A function at **80-99%
fuzzy from clean C is more valuable than a 100% byte match achieved by inline
`asm { }` blocks**. The asm-block recipes below exist for a small number of
genuine MWCC instruction-selection bugs — they are **not** the default tool
for "the diff is still red." If a residual won't yield to the one-liners and
source-form tweaks in the next two sections, commit the partial and move on.
Inline asm in production source is a code smell; we'll only keep it where a
clear MWCC compiler quirk leaves no C alternative.

Heuristic before reaching for `asm { }`:
- Is the residual a single instruction / register-allocation choice? → leave at
  partial, commit, move on.
- Is the function ≥80% fuzzy on clean C? → leave at partial, commit, move on.
- Does target's behaviour require an instruction MWCC literally cannot pick
  from any C input (e.g. specific `rlwimi` bit insert, `cmplwi` on a value
  MWCC sign-extends)? → only then is asm justified, and call it out in the
  commit message.

## High-impact one-liners (try first when a function is already 80-95%)

1. **`#pragma peephole off` + `#pragma scheduling off`** around the function
   (matched-with `#pragma peephole reset` + `#pragma scheduling reset` after).
   This alone routinely takes 80-95% fuzzy functions to 100% by disabling the
   peephole pass that fuses `extsb + cmpwi → extsb.`, `rlwinm + cmpwi →
   rlwinm.`, and similar dot-form merges. Single most useful change on this
   project. See `b7eda753` (dll_198 — 3 functions to 100%).

2. **Replace `& 0xff7f`-style literal with `& ~0x80`** for single-bit clears.
   The bit-NOT form often produces `rlwinm` directly where the explicit
   inverted-literal form produces `andi.`. See `782a09a8`, `91f5f4ab`.

3. **`*(void **)ptr != NULL` instead of `*(int *)ptr != 0`**. The pointer form
   emits `cmplwi` (unsigned); the int form emits `cmpwi` (signed). Target
   almost always uses `cmplwi` for pointer-typed compares. See `a42bb90b`.

4. **`if (v > K) v = K; return v;` instead of `if (v <= K) return v; return K;`**.
   The former produces target's `blelr` clamp pattern; the inverse form emits
   `bgt + mr + blr`, adding an instruction. See `77438a6f`.

5. **Swap local declaration order to control stack offsets.** When you take
   addresses of multiple `int` locals and pass them to a single function
   (e.g. `ObjList_GetObjects(&objectIndex, &objectCount)`), MWCC assigns stack
   offsets in declaration order. If target has `&first` at sp+8 and `&second`
   at sp+0xc but yours is the opposite, swap the declarations. See `91f5f4ab`.

6. **Lift a repeated constant load to a local before multiple stores** to force
   CSE. `f32 fz = lbl_xxx; *p1 = fz; *p2 = fz; *p3 = fz;` instead of three
   direct stores — MWCC will reload the constant each time without the lift.
   See `75660758` (ecsh_cup_init 67% → 100%).

7. **`u8` not `char` for byte arrays you load and assign without arithmetic**.
   `char buf[N]; buf[0] = arr[i];` emits a spurious `extsb`; `u8 buf[N];`
   doesn't. See `6863ffe7` and the related dll_36 commits.

8. **Wrap dead-stored stack locals in a `struct` when only the buffer head is
   passed to a callee.** Pattern: function builds `auStack_28[6]; u16 mode;
   f32 a,b,c,d;` on the stack, fills the f32 slots from globals, then passes
   `auStack_28` (just the head) to a virtual call — MWCC sees the per-field
   writes as dead (the call only "sees" a 6-byte buffer) and eliminates every
   `stfs`. Wrapping them as one struct with a `pad[6]` then passing
   `&stk.pad` keeps the stores alive because MWCC treats the whole struct as
   live through the address-taken `pad` member. Took
   `SB_Galleon_hitDetect` from 63% → 93.8% (commit `8b37ec0c`). Combine with
   `#pragma scheduling off` to align the `lfs`/`stfs` order.

9. **Declare `objRenderFn` (and similar dispatchers) with the full 6-arg
   signature** `void (*)(int *obj, int a, int b, int c, int d, f32 e)` via a
   function-pointer cast at the call site **when there's an intermediate call
   between entry and the dispatch**. Without the full signature MWCC sees only
   `r3` as live across the intermediate call and re-spills/reloads `r4..r7,f1`,
   which scrambles register allocation around the dispatch. With the full
   sig, MWCC preserves `r3..r7,f1` across the intermediate call and the
   dispatch lands on target's exact instruction sequence. Simple render fns
   *without* intermediates don't need this — args pass through naturally.
   Picked up several 100% matches in TREX_trex and DIMcannon batches.

10. **`(u32)` cast on a u8/u16 before int→f32 conversion** forces the unsigned
    path. The signed int→f32 path emits `xoris + lfd + fsubs` against a
    compiler-internal `@xxx` magic constant; the unsigned path uses the
    project's named `lbl_xxx` f64 magic (matching target). When converting an
    unsigned byte/halfword to float, write `(f32)(u32)obj->u8field` rather
    than `(f32)obj->u8field`. Picked up MoonSeedBush_init in DIMlavaball.

11. **`extern int fn(...)` for callees whose return is treated as `int`** —
    even if conceptually the return is a byte. Declaring `extern u8 fn(...)`
    triggers a spurious `clrlwi r3, r3, 24` after every call to zero-extend
    the result, which target omits. Check the asm — if there's no `clrlwi`
    after the call, the project treats the return as `int`. Picked up
    `MMP_levelcontrol_init` in DIMlavaball via `extern int getSaveGameLoadStatus`.

## Last-resort: inline `asm { }` blocks with `register` variables

**Read the Prime Directive at the top of this file first.** Use this only when
the residual is a true MWCC instruction-selection bug (e.g. specific `rlwimi`
bit insert, register-allocation order that nothing in C controls). A clean C
function at 85-99% beats an asm-forced 100% every time on this project.
Recent over-use note: leaving 9 functions matched via `asm { extsb / lis /
addi }` looks like a win on the report but leaves source nobody would
recognise as the original — that's not the goal.

When MWCC won't pick `rlwimi` / `li +/- N; and` / `cmplwi` from any C form,
drop an inline `asm` block. The pattern:

```c
{
    register u32 m;             // declared first → gets r0 (immediate slot)
    register u32 v;             // declared second → gets r3
    register int pReg = obj;    // forces the parameter into a fixed register
    /* normal C statements that precede the bit op stay outside the asm */
    asm {
        lwz v, 0x54(pReg)
        li m, -1025              // forces the "long" form vs MWCC's rlwinm
        and m, v, m
        stw m, 0x54(pReg)
    }
    /* normal C resumes */
}
```

**Critical: declaration order chooses the register.** MWCC's allocator picks
volatile regs roughly in declaration order. To match target's
`li r3, -1025; and r0, r3, r0` instead of `li r0, -1025; and r3, r0, r3`,
swap which `register u32` is declared first. This is how `CameraModeCombat_free`
and `fn_80189BE4` were taken to 100% — same body, just reordered the two
`register` lines. See `01400901`, `a42bb90b`.

For `rlwimi` (bit insert vs MWCC's `andi+ori`):

```c
{
    register u32 b;
    register u32 bitval;
    bitval = 1;                              // value to insert (0 or 1)
    asm {
        lbz b, 0x1d(t)
        rlwimi b, bitval, 5, 26, 26          // insert at bit position 5 (= 0x20)
        stb b, 0x1d(t)
    }
}
```

**`asm { }` blocks wreck nearby FP scheduling.** MWCC treats the block as an
opaque barrier and reschedules surrounding FP work around it. In a function
that mixes float stores with a bit-clear, an inline asm rlwimi can shift every
later `lfs`/`stfs` and tank the overall match. Use `asm { }` only in functions
that don't otherwise use FP regs, or place it adjacent to function entry/exit.

## Caller-side width controls extsb/extsh emission

| Source pattern | Emits |
|---|---|
| `void f(s8 type) { *p = type; if (type==2)... }` | `stb r4` + `extsb r0,r4; cmpwi r0,2` |
| `void f(int type) { *p = (s8)type; if (type==2)... }` | `extsb r0,r4; stb r0` + `cmpwi r4,2` |
| `void f(s16 v) { arr[i] = v; }` (with `u16 arr[]`) | `clrlwi r4,r4,16; sthx` |
| `void f(int v) { arr[i] = (s16)v; }` (with `s16 arr[]`) | `extsh r4,r4; sthx` |

Rule: when target's extsb/extsh appears on the *parameter side*, widen the
param type to `int` and cast at the use site. The narrow param type pushes
extension to the *use side* instead. For half-word stores, the array element
type also matters — `s16[]` triggers `extsh`, `u16[]` triggers `clrlwi`.

## FP compare operand order picks the load registers

`fcmpo cr0, f1, f0` puts the LHS of the C compare in f1 and the RHS in f0,
which then drives the order of the two `lfs` instructions before it. If the
residual diff shows the two `lfs` lines swapped, flip the compare:
`a <= b` → `b >= a`. Booleans are identical; codegen is not.

## `extern T lbl[]` for `.data` labels, scalar for `.sdata`

| Section | Declaration | Addressing |
|---|---|---|
| `.sdata` / `.sdata2` / `.sbss` | `extern int lbl_xxx;` | `lwz r3, lbl@sda21(r0)` |
| `.data` (anything not sdata) | `extern int lbl_xxx[];` | `lis ha; addi lo` |

Writing the scalar form for a `.data` symbol mis-emits sda21 and breaks every
load/store of it. Check `config/GSAE01/symbols.txt` for the section.

## `#pragma dont_inline on` for callees that live in the same TU

With `-inline auto`, MWCC inlines small functions into their callers within
the same `.c`. If the target binary keeps the `bl callee`, the caller will
never match. Wrap the callee:
```c
#pragma dont_inline on
void small_helper(...) { ... }
#pragma dont_inline reset
```

## `for (i=0; i<n; i++) { use(*p); p++; }` vs `*p++`

MWCC emits a `bdnz` countdown loop only when the increment and the
dereference are separate statements. `*p++` merges them and the loop loses
the tight `lwz; addi; cmpw; b` body that target uses. Keep `*p` and `p++`
on separate lines inside the loop body.

## Drift handling (Ghidra-imported `FUN_xxx` don't match v1.0)

Many `.c` files were imported from a v1.1 Ghidra session and have wrong
function boundaries vs the v1.0 `.s`. **Don't try to fix `FUN_xxx`** — instead:

1. Add the asm symbol as a **NEW function** in the `.c` with the correct
   name, signature, and body. The linker matches by symbol name, so the
   `FUN_xxx` floats harmlessly while your new function lands at the right
   match. See `aedc9605` (mmsh_shrine_free), `fa042933` (mmsh_shrine_render),
   `77438a6f` (fn_80189F44, fn_80189BE4).

2. **For deeper rewrites** when the .c is too misaligned: list the asm
   symbol set with `grep '\.fn ' build/GSAE01/asm/<unit>.s`, move plausible
   bodies to the right symbol names with corrected signatures, stub the
   truly-missing ones. See `dbbc5ba9` (laser19F full restructure).

3. **Use `tools/drift_audit.py <unit>`** to get a precise drift diagnosis
   before guessing. `tools/realign_skeleton.py <unit>` emits a v1.0-aligned
   skeleton.

## Vtable double-deref pattern

Target asm `lwz r4, lbl@sda21; lwz r4, 0(r4); lwz r12, 0x34(r4)` (two `lwz`s
through the variable) requires source `*(int *)lbl_xxx + 0x34`. Writing
`*(int *)&lbl_xxx + 0x34` only emits one `lwz` — the `&` flips it from
"deref the pointer-variable's value" to "load the variable's bytes," which
is one level less indirect. The matched-code convention is `extern int *lbl;`
+ `*lbl_xxx` (no `&`).

## Tooling

- `python3 tools/function_objdump.py --diff <unit> <symbol>` — per-function diff
- `python3 tools/drift_audit.py [--only-drifted] [--csv] [unit]` — find drifted units
- `python3 tools/stub_queue.py [--aligned-only] [--max-size N]` — ranked easy-win targets
- `python3 tools/realign_skeleton.py <unit> [--merge]` — v1.0-aligned skeleton
- `rm -f build/GSAE01/report.json && timeout 30 ninja build/GSAE01/report.json` — refresh report

## Reference commits

| Technique | Commit |
|---|---|
| asm{} + register-order (rlwimi/li+and) | `2e20e326`, `01400901`, `a42bb90b` |
| Add-new-function for drifted .c | `aedc9605`, `fa042933`, `77438a6f` |
| `if (v > K) v = K;` clamp form for `blelr` | `77438a6f` |
| `u8` vs `char` to drop `extsb` | `6863ffe7` |
| `& ~constant` for `rlwinm` | `782a09a8` |
| `*(void **)` for `cmplwi` | `a42bb90b` |
| `#pragma peephole off` mass fix | `b7eda753` |
| Lift temp for forced CSE | `75660758` |
| Local declaration swap for stack offset | `91f5f4ab` |
| Source-set restructure | `dbbc5ba9` |
