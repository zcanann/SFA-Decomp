# SFA-Decomp Matching Playbook (MWCC 1.2.5n, EN v1.0)

Short field-tested reference for getting MWCC-compiled C to match the target
binary. Read in 60 seconds, apply in the order they appear; the later sections
are more invasive.

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

## Last-resort: inline `asm { }` blocks with `register` variables

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

**Warning: `asm { }` blocks wreck nearby FP scheduling.** MWCC treats an
`asm` block as an opaque barrier and spills every live FP register across it.
In a function that mixes float work with a bit-clear, dropping in a 3-line
rlwimi `asm` block can drop the overall match from ~30% to <15% because every
following `lfs`/`stfs` shifts. Only reach for `asm` blocks in:
- functions that don't otherwise use FP regs, or
- positions near the function entry/exit where no live FP values surround them.
See the failed `fn_801EC870` attempt in DRcradle (b5b60577..d9ab458b).

## Sign/zero extension recipes (extsh, extsb on caller-side widths)

Two patterns from DRcradle/maketex (e4126ea5) where the param type controls
whether MWCC emits an extension instruction:

1. **`extsb r0, r4` before a byte store + `cmpwi r4, 2`**: target stores the
   sign-extended low byte but compares the wider int. Source is `int param`,
   not `s8 param`:
   ```c
   void f(int obj, int type) {            // NOT s8 type
       *(s8 *)(t + 0x421) = (s8)type;     // → extsb + stb
       if (type == 2) ...                 // → cmpwi r4, 2 (no extsb)
   }
   ```
   With `s8 type`, MWCC stores r4 raw (`stb r4`) and `extsb`+`cmpwi` the
   compare side. See `SnowBike_setType` 95.1% → 100%.

2. **`extsh r4, r4` before a `sthx` half-word store**: target sign-extends the
   value before the indexed store. Pure `s16 val` param does NOT trigger
   extsh (it emits `clrlwi` = zero-extend). Use `int val` + `(s16)val` cast,
   AND declare the destination array as `s16[]` not `u16[]`:
   ```c
   extern s16 lbl_xxx[];                 // s16, not u16
   int f(int p, int val) {                // int, not s16
       lbl_xxx[idx] = (s16)val;           // → extsh + sthx
   }
   ```
   See `fn_80080360` 0% → 100%.

## Compare operand order changes which F register holds which value

`fcmpo cr0, f1, f0` orders the operands. The C operand on the LEFT of the
compare lands in f1; the RIGHT lands in f0. So `lbl <= *p` and `*p >= lbl`
have the same boolean result but emit different `lfs` orderings, which cascade
into different `cror` patterns and bring the match from 11% to 100% (or vice
versa). When residual diff shows `lfs f1` and `lfs f0` swapped, flip the
compare operand order. See `objAnimFn_8013a3f0` (5a838940) and
`SnowBike_func12` partial.

## Forcing `lis + addi` for `.data` labels (not `sda21`)

For globals in `.data` (large data, not `.sdata`/`.sdata2`), target uses
`lis ha; addi lo` (32-bit absolute). MWCC emits `sda21` (small-data) by
default when you write `extern int lbl_80328590;`. Declare as an **array**
to force the absolute form:
```c
extern int lbl_80328590[];     // → lis + addi
extern int lbl_80328590;       // → sda21 (wrong for .data)
```
See `SnowBike_func15` (fcbf1d4d).

## `#pragma dont_inline on` is essential when call sites land in the same TU

If function `A` calls function `B` and both live in the same `.c`, MWCC with
`-inline auto` will inline `B` into `A` and the asm for `A` won't match the
target's `bl B`. Wrap `B` with `#pragma dont_inline on / reset`. This unlocked
`SnowBike_setType` (244b) which kept inlining the 184b `fn_801EC870`. See
DRcradle commits (6e7203a0).

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
