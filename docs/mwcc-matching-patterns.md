# MWCC Matching Patterns — Field Notes

A working guide to getting MWCC 1.3.2 (`-O4,p`) to emit byte-identical code to
Star Fox Adventures retail. Collected while grinding through `src/track/intersect.c`.

Most of this is compiler-behavior folklore. None of it is magic, but a lot of it
is non-obvious until you've hit the wall a few times.

---

## Table of contents

1. [Setup and workflow](#setup-and-workflow)
2. [Reading the diff](#reading-the-diff)
3. [The four pragmas](#the-four-pragmas)
4. [Extern declarations — the biggest lever](#extern-declarations--the-biggest-lever)
5. [Parameter types affect codegen more than you'd think](#parameter-types-affect-codegen-more-than-youd-think)
6. [GXColor and other small-struct-by-value quirks](#gxcolor-and-other-small-struct-by-value-quirks)
7. [Switch / jumptable matching](#switch--jumptable-matching)
8. [Float / fixed-point conversions](#float--fixed-point-conversions)
9. [Stack layout and local ordering](#stack-layout-and-local-ordering)
10. [Things you usually cannot control](#things-you-usually-cannot-control)
11. [Workflow tips](#workflow-tips)

---

## Setup and workflow

### Prerequisites
- Compiler: `mwcceppc.exe` 1.3.2 running under `wibo` (macOS/Linux) or Windows
- Build system: ninja + `tools/project.py`
- Diff tool: `objdiff` / `objdiff-cli`

### The edit loop

```sh
# Edit src/track/intersect.c
ninja                       # build
python3 -c "import json; ..." # check match % in build/GSAE01/report.json
objdiff-cli diff -p . -u main/track/intersect <symbol>   # inspect diff
```

One-liner for fuzzy match percent of a single symbol:

```sh
python3 -c "
import json
r = json.load(open('build/GSAE01/report.json'))
for u in r['units']:
    if u['name']=='main/track/intersect':
        for f in u['functions']:
            if f['name']=='fn_XXXXXXXX':
                print(f['name'], f.get('fuzzy_match_percent','ABSENT'))
                break
        break
"
```

### Symbol naming

- `fn_XXXXXXXX` (lowercase `fn_`, uppercase hex) — canonical name in
  `config/GSAE01/symbols.txt`. Use this in both the function definition and the
  header prototype once you port a function.
- `FUN_xxxxxxxx` / `DAT_xxxxxxxx` — Ghidra's default names. These are
  placeholders until you rename to the retail symbol.

If your C name doesn't match the symbols.txt entry, the linker will emit the
function at a different address and objdiff will show `ABSENT` (no percent).
Always rename.

---

## Reading the diff

Most of the match/no-match calls come down to reading objdiff output. A
template for getting a tight side-by-side:

```sh
objdiff-cli diff -p . -u "main/track/intersect" fn_XXXXXXXX -o - --format json-pretty > /tmp/diff.json
python3 << 'EOF'
import json
d = json.load(open('/tmp/diff.json'))
def fmt(ins):
    return ins.get('instruction',{}).get('formatted','?') if 'instruction' in ins else '---'
l = [s for s in d['left']['symbols']  if s['name']=='fn_XXXXXXXX'][0]
r = [s for s in d['right']['symbols'] if s['name']=='fn_XXXXXXXX'][0]
li = [fmt(i) for i in l['instructions']]
ri = [fmt(i) for i in r['instructions']]
for i in range(max(len(li), len(ri))):
    lv = li[i] if i < len(li) else ''
    rv = ri[i] if i < len(ri) else ''
    if lv != rv:
        print(f"!! {i:3d}: {lv:50s}  |  {rv}")
EOF
```

Things to look for:
- **Same instructions, swapped register numbers** → register allocation issue.
  Sometimes fixable by reordering locals, usually not.
- **Extra `clrlwi`, `extsh`, `mr` instructions on one side** → narrowing /
  scheduling / peephole. Often fixable.
- **`cmpwi` vs `cmplwi`** → signed vs unsigned int type.
- **`bge` vs `cror eq,lt,eq; bne`** → unordered vs ordered FP compare, or
  comparison-direction choice in source.
- **Different stack offsets** → you have more (or fewer) locals than target.
- **Different branch target addresses** with the SAME mnemonics → these are
  just relative addresses and not a real diff. The function sits at a different
  link offset in your `.o`.

---

## The four pragmas

MWCC 1.3.2 has four knobs that matter for matching. Use them on a
function-by-function basis, wrapping only the function you care about:

```c
#pragma peephole off
#pragma scheduling off
void fn_XXXXXXXX(...) {
    ...
}
#pragma scheduling reset
#pragma peephole reset
```

### `#pragma scheduling off`
Disables the instruction scheduler. Use when you see the right instructions but
in the wrong order — typically the compiler reordering loads, stores, and
register moves relative to each other.

**Symptoms it fixes:**
- `mr rN, rM` instructions drifting earlier or later than target
- `cmplwi` moved before the `stb` target has after
- "Same instructions, different order"

**Default answer** when you see a scheduling diff. It costs nothing to add, so
when in doubt, try it first.

### `#pragma peephole off`
Disables the peephole optimizer. This is the bigger hammer. Disables things like:

- Folding `clrlwi r0,X,24; cmplwi r0,0; beq` into `clrlwi. r0,X,24; beq`
- Folding `mr rN,X; cmpwi rN,0; beq` into `mr. rN,X; beq`
- Default-value hoisting in early-return patterns
- Some constant-folding across independent statements

**Symptoms it fixes:**
- Target has separate `clrlwi` + `cmplwi` + `beq`; yours has `clrlwi.` + `beq`
- Target hoists a `li rN, default` into the prologue; yours does the same
  but target expects the default to be set lazily
- Target has explicit `addi r4, r4, 0x1c0` mid-loop; yours collapses adjacent
  `+= 0x1c0` statements into a single final `+= 0x380`

**Cost:** peephole-off occasionally makes things worse for other patterns. If
a function gets worse with peephole off, turn it back on.

### `#pragma optimize_for_size on`
Suppresses loop unrolling.

**Symptoms it fixes:**
- Your loop has `ctr = N/2` and the body appears twice (MWCC unrolled 2x); target
  has `ctr = N` with body appearing once
- Byte-count of your function is noticeably larger than target

### (Note) `#pragma fp_contract off`
Exists; sometimes useful for FP-heavy code where MWCC fuses `fmadd` /
`fnmsub`. Rarely needed in collision / rendering code.

---

## Extern declarations — the biggest lever

How you declare an `extern` drastically changes the emitted addressing mode and
narrowing behavior.

### Narrow-typed externs for sbss / sdata

```c
extern u8  lbl_803DDC91;  // forces lbz/stb
extern u16 lbl_803DDC80;  // forces lhz/sth
extern u32 lbl_803DDCB0;  // forces lwz/stw
extern s32 lbl_803DC360;  // same, but enables cmpw (signed) on reads
extern f32 lbl_803DFB5C;  // forces lfs/stfs
```

Declaring a small static as `int` when the real type is `u8` gets you `lwz`
when target has `lbz`. Match the retail size in `symbols.txt` (`data:byte`,
`data:4byte`, `data:float`).

### Array-decay externs for large bss

This one bites almost every time:

```c
// BAD — MWCC thinks it's a small sdata object and emits @sda21
extern u8 lbl_80393A40;

// GOOD — MWCC emits @ha/@l (correct for a 14KB bss array)
extern u8 lbl_80393A40[];
```

The array form suppresses sda21 promotion. Use it for anything larger than
~sda21-reachable, which in practice is most `.bss` objects.

### Unified base pointer for adjacent globals

Target often uses ONE register (e.g. r31) to hold a base address and indexes
into several adjacent symbols:

```asm
lis  r3, lbl_80392A20@ha
addi r31, r3, lbl_80392A20@l        ; r31 = 0x80392A20 (lbl_80392A20)
...
addi r3, r31, 0x1020                ; = 0x80393A40 (lbl_80393A40)
addi r3, r31, 0x0020                ; = 0x80392A40 (lbl_80392A40)
stw  r0, 0x10(r31)                  ; = lbl_80392A30
lfs  f0, 0x0(r31)                   ; = lbl_80392A20
```

This happens because the retail source treats them as a single struct, or uses
explicit pointer arithmetic from one base. To match, pick the earliest symbol
as your base:

```c
extern u8 lbl_80392A20[];
u8* base = lbl_80392A20;
u8* a    = base + 0x1020;           // lbl_80393A40
u8* b    = base + 0x0020;           // lbl_80392A40
*(u32*)(base + 0x10) = ...;         // lbl_80392A30
*(f32*)(base + 0x0)  = ...;         // lbl_80392A20
```

Declaring each global separately and `&lbl_80392A40` / `&lbl_80393A40` will
generate independent `lis/addi` pairs — no register sharing.

### Unprototyped externs to dodge narrowing

When a function takes a narrow type (`u8`/`GXBool`) but target passes a wider
value:

```asm
; target
mr   r3, r31           ; just pass it, no narrowing
bl   GXSetZCompLoc
```
```c
// original, emits extra clrlwi:
GXSetZCompLoc(param_1);

// hack — local unprototyped extern forces "default argument promotions",
// which for u32 means no narrow needed:
extern void GXSetZCompLoc();
GXSetZCompLoc(param_1);
```

The `extern void fn();` (with empty parentheses — K&R style) tells MWCC to use
unprototyped calling, which skips narrowing. Only use this locally inside the
function that needs the hack.

---

## Parameter types affect codegen more than you'd think

### `int` vs `u32` for equality-with-zero

```asm
; target
cmpwi  r3, 0x0    ; signed compare
; your build
cmplwi r3, 0x0    ; unsigned compare
```

Same semantics for zero, different encoding. MWCC picks based on operand type:
- `u32` → `cmplwi`
- `int` / `s32` → `cmpwi`

Matching the retail source's choice matters. If target uses `cmpwi`, declare
the parameter as `int`.

### `char` vs `u8` for function parameters

```asm
; target (u8):
clrlwi r0, r31, 24
cmplwi r0, 0x0

; your build (char):
extsb. r0, r31
```

`char` is signed in this compiler — MWCC emits `extsb` (sign-extend byte).
`u8` emits `clrlwi` (zero-extend). Match the retail source. If you're not
sure, try both and keep the one that matches.

### Widening params for CSE-free narrow stores

Useful in the `fn_8007DADC` pattern:

```asm
; target — narrows ONCE, uses narrowed value for both stb AND cmpwi
clrlwi r0, r3, 24
stb    r0, lbl_..@sda21
cmplwi r0, 0
bnelr
```

To get the shared-narrow pattern, declare the parameter as `u32` and take the
`(u8)` explicitly via a local — MWCC will CSE them:

```c
void fn(u32 param_1) {
    u8 v = (u8)param_1;
    lbl_something = v;
    if (v != 0) return;
    ...
}
```

If you instead have `u8 param_1` and store it directly, MWCC sees the low-byte
store and elides the `clrlwi`. Widening forces the narrow to exist as a value.

---

## GXColor and other small-struct-by-value quirks

`GXColor` is `{u8 r,g,b,a}` — exactly 4 bytes. MWCC on PowerPC EABI passes it
"by value" but materializes it on the caller stack and passes a POINTER. This
introduces extra stack slots.

### The direct-deref trick

Bad:
```c
u32 tmp = *colorPtr;
GXSetTevKColor(0, *(GXColor*)&tmp);
```
This makes TWO stack slots: one for `tmp`, one for the arg-area copy MWCC
materializes for the call. The diff shows paired `stw` instructions.

Good:
```c
GXSetTevKColor(0, *(GXColor*)colorPtr);
```
MWCC reads directly from the pointer, spills once to the arg area, and passes
that pointer. Matches the typical retail pattern exactly.

### Struct-field init for multi-byte writes

For cases like `RGB[0] = p->r; RGB[1] = p->g; RGB[2] = p->b;`:

```c
// GOOD — matches "cached sda21 base" pattern
param_1[0] = lbl_803DDC9C.r;
param_1[1] = lbl_803DDC9C.g;
param_1[2] = lbl_803DDC9C.b;
```

Add `#pragma scheduling off` to pin the `li r4, lbl@sda21` cache instruction
between the sda21 loads. Without it, MWCC emits three independent sda21 loads;
with it, it caches the base.

---

## Switch / jumptable matching

Several cases matter here.

### Case block ordering matches source order

MWCC emits switch case blocks in the order they appear in source. If the
retail jumptable points to blocks at ascending offsets in target:

```
jumptable_8030F68C:
    case  0: +0x130  ; physical offset 0x130 → body "DC360=6"
    case  8: +0x13C  ; physical offset 0x13C → body "DC360=4"
    case 10: +0x118  ; physical offset 0x118 → body "DC360=2"
    case 11: +0x10C  ; physical offset 0x10C → body "DC360=1"
    case 13: +0x148
```

The PHYSICAL layout goes 0x10C (11=DC=1), 0x118 (10=DC=2), 0x130 (0=DC=6),
0x13C (8=DC=4), 0x148 (13). So retail source ordered cases: **11, 10, 0, 8,
13**, not numeric order. To match, order your cases the same way.

### Jumptable range matches max case

```c
// MAX case = 12, bounds check: (val > 12) → default
case 11:
case 12:
    ...
default:
    ...
```

If target has `cmplwi r0, 0xd` (bounds=13), you need an explicit case 13 even
if it shares the default body:

```c
case 11: case 12: ...
case 13:
default:  ...
```

### Fallthrough vs aliased jumptable entries

Same-body consecutive cases (`case 11: case 12:`) → one physical block,
jumptable entries for 11 and 12 point to same address.

Same-body non-consecutive cases (`case 2:` and `case 3:` with identical
bodies) → MWCC emits them as separate blocks in target. Write them
separately in source; do not merge.

---

## Float / fixed-point conversions

### `(f32)(u32)value` generates the bias trick

```asm
stw    r5, 0xc(r1)       ; store low word
lis    r0, 0x4330
stw    r0, 0x8(r1)       ; store magic high word (2^52 exponent)
lfd    f0, 0x8(r1)       ; load as double
fsubs  f0, f0, f3        ; subtract bias constant
```

This is the standard PPC u32→float conversion. Your `(f32)(u32)x` will emit it;
so will target.

### CSE eats the expression

If you write:
```c
if ((f32)(u32)x - step <= 0.0f) { ... }
else { a[0] = (s32)((f32)(u32)x - step); }
```
MWCC CSEs the conversion — both branches use the cached `f2`. Target sometimes
RECOMPUTES the conversion in the `else` branch. Preventing MWCC CSE here is
hard; you usually can't crack it without `__asm`. Accept the partial match.

### Float→short via fctiwz

```asm
fctiwz f0, f1
stfd   f0, 0x10(r1)
lwz    r0, 0x14(r1)     ; load the low word = the int value
sth    r0, ...
```

Write as:
```c
GXWGFifo.s16 = (s32)somefloat;
```
(Not `(s16)(s32)` — that adds a redundant `extsh`.)

---

## Stack layout and local ordering

### Last declared = lowest stack offset

MWCC allocates locals in REVERSE declaration order. If target has
`memSize` at stack+0xc and `sectorSize` at stack+0x8:

```c
// MATCHES target
s32 memSize;      // ends up at +0xc (higher address)
s32 sectorSize;   // ends up at +0x8 (lower, allocated later)
```

Flipping the declaration order swaps the stack slots. This matters when the
function passes pointers to both as arguments — the arg register assignment is
determined by declaration order.

### Fewer locals = smaller stack frame

If your function saves an extra callee-save (`r29` when target only uses
`r30`, `r31`), it's usually because you have a local that survives across a
call and target doesn't. Reducing intermediate `int res` locals by
restructuring helps but is often impossible without changing semantics.

---

## Things you usually cannot control

Some diffs are effectively uncrackable without inline `__asm`:

1. **FP register allocation order** — target allocates f24→f31, mine allocates
   f31→f24 (or vice versa). This is deep in MWCC's live-range analysis.

2. **`li r0, N; cmpw rX, r0` vs `cmpwi rX, N`** — target materializes the
   compare immediate into r0 first; yours uses the cmpwi immediate form.
   MWCC strongly prefers the immediate form; hard to force the materialize.

3. **Caching the sda21 base in a callee-save register across calls** — when
   target holds an address in r31 across a function call but yours recomputes
   the base after the call. The register allocator decides this based on
   heuristics.

4. **CSE of an expression MWCC sees as "cheap"** — any time target emits the
   same expression twice but your compiler caches it in a register.

Accept these as-is once you've verified the semantics are equivalent.
A 97% match on a 500b function with only register-alloc diffs is a clean port.

---

## Workflow tips

### Attacking a new function

1. **Check the size** in `symbols.txt`. Small (< 100b) and large (> 1000b) are
   both fun; 200-500b is usually the sweet spot for matching.

2. **Read the asm** before looking at Ghidra output. Identify the pattern:
   getter/setter, cache wrapper, state machine, render helper, math.

3. **Map the FUN_8025xxxx calls** to their real GX symbol names via
   `symbols.txt`. Nothing matches until you're calling the right function.

   ```sh
   grep -iE "8025c828|8025be80|..." config/GSAE01/symbols.txt
   ```

4. **Sketch the C** based on Ghidra's decompile as a starting point, but
   expect to rewrite it. Ghidra's casts are often wrong or too aggressive.

5. **Rename**. `FUN_xxxxxxxx` → `fn_XXXXXXXX` in both the definition and
   the header, then check the match percentage — if `ABSENT`, symbols don't
   match.

6. **Iterate**. Try:
   - `#pragma scheduling off` first
   - Add `#pragma peephole off` if scheduling alone didn't finish it
   - Check parameter types (int vs u32, char vs u8)
   - Check extern types for narrowing
   - Check local declaration order for stack layout

### Commit hygiene

- One function per commit (or one logical batch of siblings).
- Commit message should note what pattern was used and what remains if
  partial. Future-you will thank present-you when revisiting.
- Partial matches are fine and worth committing — they document the wall
  you hit and let the next person pick up without rediscovering.

### Sibling batching

Once you match one render-state function with a particular pattern
(ZMode cache + TEV chain + BlendMode + ...), look for nearby functions with
the same shape. `fn_800788BC`, `fn_80078988`, `fn_80078A58`, `fn_80078B28`,
`fn_80078BF8`, `fn_80078CC8` are all the same template with different
constants — porting them as a batch is much faster than one at a time.

---

## Cheat sheet

| Symptom | Likely fix |
| --- | --- |
| Instructions correct, wrong order | `#pragma scheduling off` |
| `clrlwi.` / `mr.` / `addic.` | `#pragma peephole off` |
| `@sda21` vs `@ha/@l` on a bss symbol | `extern u8 foo[];` (array decay) |
| `cmplwi` vs target's `cmpwi` | declare as `int` instead of `u32` |
| `extsb` vs target's `clrlwi` | declare as `u8` instead of `char` |
| `GXSetTevKColor` has 2x the stw pairs | `*(GXColor*)colorPtr` direct deref |
| Jumptable bounds wrong | add missing `case N:` before `default:` |
| Three independent `lis/addi` for adjacent globals | unified base pointer |
| Loop body appears 2x | `#pragma optimize_for_size on` |
| Default-hoisted into prologue via `beqlr` | `#pragma peephole off` |
| Arg narrowing on call that target doesn't do | local `extern void fn();` |
| Extra `mr` on entry | may be inherent; try reordering args in signature |
| CSE of float expression between compare and store | usually uncrackable |

---

## Appendix: pattern examples from intersect.c

### A. Cached-base RGB getter — `fn_80070658`

Target pattern:
```asm
lbz  r0, lbl_803DDC9C@sda21(r0)
stb  r0, 0x0(r3)
li   r4, lbl_803DDC9C@sda21       ; cache base
lbz  r0, 0x1(r4)
stb  r0, 0x1(r3)
lbz  r0, 0x2(r4)
stb  r0, 0x2(r3)
```

Match via:
```c
#pragma scheduling off
void fn_80070658(u8* param_1) {
    param_1[0] = lbl_803DDC9C.r;
    param_1[1] = lbl_803DDC9C.g;
    param_1[2] = lbl_803DDC9C.b;
}
#pragma scheduling reset
```

### B. GX state cache — `fn_80070434`

Target pattern:
```asm
lbz    r3, lbl_803DDC91@sda21(r0)
clrlwi r0, r31, 24
cmplw  r3, r0
bne    .L_update
lbz    r0, lbl_803DDC99@sda21(r0)
cmplwi r0, 0
bne    .L_exit
.L_update:
mr     r3, r31                 ; pass raw r31, no narrow!
bl     GXSetZCompLoc
...
```

Match via:
```c
#pragma scheduling off
void fn_80070434(u32 param_1) {
    extern void GXSetZCompLoc();  // unprototyped → no narrow on call
    if ((u32)lbl_803DDC91 != (param_1 & 0xff) || lbl_803DDC99 == 0) {
        GXSetZCompLoc(param_1);
        lbl_803DDC91 = (u8)param_1;
        lbl_803DDC99 = 1;
    }
}
#pragma scheduling reset
```

### C. bss init via single base pointer — `fn_8006FE48`

```c
extern u8 lbl_80392A20[];   // treat as a single "struct" base
...
u8*  base = lbl_80392A20;
u8*  a = base + 0x1020;     // lbl_80393A40
u8*  b = base + 0x0020;     // lbl_80392A40
...
*(u32*)(base + 0x10) = fn_80054ED0(0x19);  // lbl_80392A30 (adjacent)
*(f32*)(base + 0x00) = lbl_803DFADC;        // into lbl_80392A20 itself
```

### D. Jumptable dispatch — `fn_8006F504`

11-entry jumptable (cases 0..10), cases 9-10 aliased with case 8:
```c
#pragma scheduling off
void* fn_8006F504(u32 i) {
    extern u8 lbl_8030F470[];
    u8* base = lbl_8030F470;
    switch (i) {
        case 0:  return base;
        case 1:  return base + 0x14;
        case 2:  return base + 0x3C;
        case 3:  return base + 0x64;
        case 4:  return base + 0x50;
        case 5:  return base + 0x78;
        case 6:  return base + 0x8C;
        case 7:  return base + 0xA0;
        case 10:
        case 8:  return base + 0x28;
        default: return base + 0x28;
    }
}
#pragma scheduling reset
```

The `case 10: case 8:` ordering (10 before 8) forces max case = 10, extending
the jumptable range to 11 entries.

### E. Direct-deref GXColor pattern — `fn_80073C28`

```c
// instead of:
//   u32 tmp = *colorA;
//   GXSetTevKColor(0, *(GXColor*)&tmp);
// just:
GXSetTevKColor(0, *(GXColor*)colorA);
```

Eliminates the intermediate stack slot; saves 0x10 bytes of frame size and
matches target.
