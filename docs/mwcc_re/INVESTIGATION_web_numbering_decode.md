# Web-numbering decode — the 0x4c2932 walk does not exist; numbering is a list-order pass

Completes the decode requested in `docs/mwcc_re/INVESTIGATION_dll14_residuals.md` (last section).
Binary: `build/compilers/GC/2.0/mwcceppc.exe` (pei-i386, image base 0x400000, flat VAs).
All disassembly via `objdump -d --start-address=… --stop-address=…` per docs/mwcc_re/README.md.
Honesty rule applied: every inferred name is tagged `[inf]`.

## 0. REFUTATION FIRST: `ra=0x4c2932` is a stale stack slot, not a return address

`tools/mwcc_re/pri_trace_lldb.py` breaks at **0x4fe563** and logs `ra = [rsp]`. But 0x4fe563 is
NOT at function entry. The commit function's real entry is **0x4fe550**:

```
4fe550: 53                push  ebx            ; entry esp = X, [X] = real RA
4fe551: 56                push  esi
4fe552: 57                push  edi
4fe553: 55                push  ebp
4fe554: 83 ec 08          sub   esp, 8         ; esp = X-24
4fe557: ff 74 24 1c       push  dword [esp+0x1c] ; arg1 = object
4fe55b: e8 f0 1b fd ff    call  0x4d0150       ; GetDesc(obj) [inf]
4fe560: 59                pop   ecx            ; esp back to X-24
4fe561: 89 c3             mov   ebx, eax       ; ebx = desc
4fe563: 83 3d 00 99 5e 00 00  cmp dword [0x5e9900], 0   ; <<< pri_trace breakpoint
```

At the breakpoint, `esp = X-24`, so `[esp]` is the first dword of the 8-byte **local scratch
area** — uninitialized, holding whatever an earlier, deeper call chain left there. The real
return address is at `[esp+24]` and is ALWAYS `0x4d0556` (see §2: 0x4fe550 has exactly one
caller). The constant `0x4c2932` was residue of `call 0x4e77e0` at `0x4c292d` (a CMachine.c
size-classification helper wrapper at 0x4c2920, unrelated to numbering) executed earlier at the
same stack depth. The "single deterministic machine-emission walk at 0x4c2932" therefore does
not exist. What IS true: all commits do come through one uniform call path — but it is the
**CodeGen in-order numbering pass**, decoded below.

The prior conclusion in the investigation doc ("webIndex = order the code generator first
touches each value while emitting PCode") is **retracted** by this decode. Numbering happens in
ONE pass BEFORE instruction emission, and the order key is **list position**, not emission
touch order.

## 1. The commit function 0x4fe550 [inf: `assign_register_by_class`]

```
4fe563: cmp   dword [0x5e9900], 0        ; virtual-register mode? (set to 1 per function, §4)
4fe56a: je    0x4fe581                   ; not virtual -> allocate a real free register
; virtual mode:
4fe56c: movsx eax, byte [esp+0x20]       ; cls (arg2)
4fe571: mov   ebp, [0x5e9b04 + eax*4]    ; webIndex = webEnd[cls]
4fe578: inc   dword [0x5e9b04 + eax*4]   ;            webEnd[cls]++
4fe57f: jmp   0x4fe5ef
; non-virtual mode (0x4fe581..0x4fe5e7): scan free physical regs (0x5e5c78 use-matrix),
; call 0x4d0fe0 to claim one — this is the -O0/inline-asm path, not ours.
4fe5ef: or    byte [ebx+0x24], 2         ; desc.flags |= ASSIGNED [inf]
4fe5f3: mov   al, [esp+0x20]
4fe5f7: mov   [ebx+0x25], al             ; desc.class = cls
4fe5fa: mov   [ebx+0x26], bp             ; desc.reg16 = webIndex
```

Globals: `0x5e9b04[cls]` = webEnd counters (what pri_trace reads); `0x5e9900` = virtual-mode
flag. The reset fn **0x4fe610** (called once per function from the driver, 0x433563) zeroes the
physical-use matrix, sets `webEnd[cls] = 0x5e9800[cls]` (per-class base; empirically 34 for
GPRs = the observed start of the named band) and sets `0x5e9900 = 1`.

## 2. The one and only call chain

Byte-scan of every `e8 rel32` in .text:

- `0x4fe550` (commit) has exactly ONE caller: **0x4d0551**, inside **0x4d03a0** (RegisterInfo.c)
  [inf: `Register_AssignVirtual(obj)`] — classifies `obj->type` into class (desc+0x25: 4 = GPR,
  3 = GPR pair (8-byte int), 2 = FPR (type code 4, size codes 4..0xe), 5 = none), gets/creates
  the 0x2a-byte desc (obj+0x2a for class-1 objects, obj+0x32 otherwise; desc+4 = pri,
  +0x22 = in-memory byte, +0x23 = register-candidate byte, +0x24 = flags, +0x25 = class,
  +0x26 = reg/webIndex), and **gates on `0x5e9c88[cls] > 0`** (remaining physical registers of
  that class; ≥2 for pairs via 0x4d0270) before committing.
- `0x4d03a0` has 10 callers: 8 in CodeGen.c (0x4357c5, 0x4359cf, 0x435cd2, 0x435d77, 0x435dd9,
  0x435e45, 0x435eb5, 0x435eee) + 2 in FuncLevelAsmPPC.c (inline-asm only).

## 3. The numbering functions (CodeGen.c) and the driver decision

Driver = CodeGen per-function main [inf: `codegenfunc`], fragment at **0x43361d**:

```
43361d: cmp  dword [0x5e9900], 0
433624: je   0x433630
433626: call 0x435d20        ; virtual mode  -> IN-ORDER PASS (ours, -O4)
43362b: jmp  0x433648
433630: call 0x435a10        ; non-virtual   -> priority worklist, GPR   (cls 4)
433638: ...  call 0x435810   ;                                  GPR pair (cls 3)
433643: call 0x435650        ;                                  FPR      (cls 2)
```

**The max-priority worklists (0x435650/0x435810/0x435a10 — the `CodeGen_NumberWebs` family
described in `recovered/CodeGenNumbering.c`) only run when `0x5e9900 == 0`, i.e. NOT in the
graph-coloring configuration.** For every -O4,p compile they are dead code, which is exactly
why the collaborator's trace never saw them fire. Priorities (desc+4) do not order anything in
our compiles; pri is only an eligibility gate (see loop 5 below).

### The in-order pass 0x435d20 [inf: `number_all_webs_inorder`] — annotated

```
; ---- loop 1: list 0x5e9d48 ----------------------------------------------
435d23: mov  ebx, [0x5e9d48]             ; pre-scan list (see §5)
435d30: mov  ebp, [ebx+4]                ; obj
435d34: call 0x4d0150                    ; desc = GetDesc(obj)
435d3a: cmp  byte [eax+0x23], 0          ; register-candidate? (set by IrOptimizer 0x42e4xx)
435d3e: je   skip
435d40: cmp  byte [eax+0x22], 0          ; not forced-to-memory?
435d44: jne  skip
435d46..435d6d:                          ; rcflags = (type is ptr 0xb/0xc) ? type+0xa : obj+0x12
                                         ; skip if rcflags & 2 (volatile/address-taken [inf])
435d6f: cmp  word [eax+0x26], 0          ; not already assigned (params are, §6)
435d74: jne  skip
435d76: push ebp
435d77: call 0x4d03a0                    ; ASSIGN  (ra2 = 0x435d7c)
435d7d: mov  ebx, [ebx]                  ; next
; ---- marker A -------------------------------------------------------------
435d83: call 0x4d01f0                    ; records webEnd[cls]-1 per class into 0x5ea1b2/b4/b6
                                         ; = "last index before the locals band" [inf]
; ---- loop 2: LOCALS list 0x5e9b00 (identical eligibility) -----------------
435d88: mov  ebx, [0x5e9b00]
...
435dd9: call 0x4d03a0                    ; ASSIGN  (ra2 = 0x435dde)
; ---- loop 3: TEMPS list 0x5e99c4, partition A -----------------------------
435de5: mov  ebx, [0x5e99c4]
435df3: mov  eax, [ebp+0xa]              ; obj->name [inf]
435df7: call 0x4e9380                    ; name starts with '@' (0x40) or '$' (0x24)?
435dfd: test al, al
435dff: jne  skip                        ; -> only ORDINARY-NAMED temps assigned here
...
435e45: call 0x4d03a0                    ; ASSIGN  (ra2 = 0x435e4a)
; ---- loop 4: TEMPS list 0x5e99c4, partition B -----------------------------
435e56: mov  ebx, [0x5e99c4]
435e67: call 0x4e9380
435e6f: je   skip                        ; -> only '@'/'$'-NAMED temps (SR/backend clones)
...
435eb5: call 0x4d03a0                    ; ASSIGN  (ra2 = 0x435eba)
; ---- marker B: 0x4d0220 records webEnd[cls] into 0x5e9738/3c/40 -----------
435e51: call 0x4d0220
; ---- loop 5: list 0x5e978c (TOC.c-built address objects [inf]) ------------
435ec1: mov  esi, [0x5e978c]
435eda: cmp  word [eax+0x26], 0 ; jne skip
435ee1: cmp  byte [eax+0x23], 0 ; je  skip
435ee7: cmp  dword [eax+4], 1           ; pri > 1  (THE pri=2 gate the trace saw on cd-base)
435eeb: jle  skip
435eed: push ebp
435eee: call 0x4d03a0                    ; ASSIGN  (ra2 = 0x435ef3)
```

The temp-name predicate **0x4e9380**: returns true iff `obj->name && (name[0]=='@' ||
name[0]=='$')`. Backend temps are created with `'@' + decimal(counter 0x5dfbbc)` names
(creation site 0x4e49a9..: `movb $0x40,[esp+8]` then a divide-by-10 ASCII loop) — these are the
familiar `@N` symbols.

## 4. List construction = the order key

All three main lists are **head-prepended singly-linked lists**, and the numbering pass walks
them **head→tail**. Therefore, within each band, **webIndex ascends in REVERSE creation
order**: the LAST-created eligible object gets the band's LOWEST index; the FIRST-created gets
the HIGHEST.

- **Locals `0x5e9b00`** — appended in CFunc.c when the local's Object is processed
  (0x4f0e15-0x4f0e4f). An alternative insert-after-head branch exists but is dead: its
  predicate 0x55ba70 is `xor eax,eax; ret` in GC/2.0. Creation order = declaration-processing
  order (user decls in lexical order; block-scoped decls when reached; CInline-generated copies
  when inlined). This mechanically produces the long-observed **"named webs: decl order
  descending"**: first-declared → deepest in list → walked last → highest index.
- **Temps `0x5e99c4`** — prepended at creation by 0x4e91f0 [inf: `make_temporary_object`]
  (callers: CFunc, StackFrame, StructMoves, CInline, and via the 0x4e49ac wrapper the
  backend loop passes; template's name copied to obj+0xa). Two numbering sub-bands (§3):
  ordinary-named temps first, `@`/`$`-named temps second.
- **`0x5e9d48`** — rebuilt per function by 0x4dd650 (called from the driver at 0x433569, right
  after the counter reset): a forward statement walk that calls 0x4dd960 on each statement's
  `stmt+0x12` chain (nodes with kind byte at +0x1c, objects at +4/+8), appending class-1 objects
  first-reference-dedup'd. **[inf] Empty for ordinary C functions** — evidence: every observed
  trace has the named band starting exactly at the class base (34), leaving zero room for a
  loop-1 band; the same statement dispatcher is what sets the has-inline-asm flag 0x5ea37c
  (kind 0xe), so the `stmt+0x12` operand chains are plausibly the inline-asm operand lists.
  This is the one link not pinned by direct evidence (dynamic run blocked, §8).
- **`0x5e978c`** — built in TOC.c (appends at 0x4e0b90/0x4e0c63/0x4e0d2e, which also set
  desc+0x23=1). Only entries with **pri ≥ 2** number here — matches the observed cd-base
  commit at `pri=2`, the eligibility minimum.

Params never appear in these bands: StackFrame.c (0x4fa050, driver site 0x4335f0) assigns them
**physical registers** via 0x4d0fe0/0x4d0ea0 (asserts reg < 0x20, decrements the class budget
0x5e9c88[cls], no webEnd touch) — physical indices sit below base 34, giving the observed
"params first" pop precedence.

Webs created AFTER this pass (du-chain splits, spill temps, InterferenceGraph 0x57b470-created
webs) take `webEnd[cls]++` at their creation moment and therefore **append above every band** —
this is the observed "renumbered into the appended band ~idx 88-90 regardless of decl position"
for self-reassign splits.

## 5. THE TRAVERSAL RULE (precise statement)

> **webIndex[cls] is assigned by one pre-emission pass in CodeGen (0x435d20), walking
> head-prepended object lists head→tail: (band 0) physical/param precolors below base;
> (band 1) the per-function pre-scan list 0x5e9d48 (empty for plain C [inf]); (band 2) eligible
> locals in REVERSE DECLARATION order — i.e. index descends in decl order; (band 3) eligible
> ordinary-named temporaries in REVERSE CREATION order; (band 4) `@`/`$`-named compiler
> temporaries (SR clones, CSE bases, conversion temps) in REVERSE CREATION order; (band 5)
> TOC-materialization objects with ref-weight pri ≥ 2, reverse creation order. Anything created
> later (web splits, spills) appends above all bands.**

Not def-time order, not first-operand-use order, not entry-block enumeration, and NOT the
machine-emission walk: emission order is irrelevant for named locals; only (a) which list an
object lands in, (b) its creation time relative to its list-mates, and (c) eligibility, matter.

SR/clone values slot in as band 4 (their `@N` names route them to the second temp sub-pass);
their relative order is fixed by the loop-optimizer's creation sequence, reversed.

## 6. SOURCE-LEVEL STEERING RULES

Within-band position = `#eligible same-class list-mates created AFTER me`. So:

1. **Named local ↕ named local** (band 2): declaration order — already the project's #34 lever.
   Now proven mechanical; note it is *declaration-processing* order, so a block-scoped decl
   numbers as of the block position (the known decl-HOIST/block-SCOPE lever), and inline
   expansion inserts its copies at the (later) inline point → below all earlier user decls.
2. **Raise a named local's index by +1 without reordering existing decls**: introduce one NEW
   eligible (actually-used, register-candidate) local declared AFTER it; every eligible local
   declared after X pushes X's index up by exactly 1. Symmetrically, making a local ineligible
   (dead, address-taken `&x`, volatile) drops it from numbering and pulls every
   earlier-declared local's index down by 1.
3. **SR temp ↕ SR temp** (band 4): reverse creation order. The last `@` temp created gets
   `named-top+1`. Source control = change what the loop optimizer clones and in which textual/
   loop order it encounters the candidates (the investigation's validated indexed-form
   rewrites); adding one more clone-inducing construct that is processed LATER pushes all
   earlier-created `@` temps up by 1 (and vice versa).
4. **Cross-band moves are impossible by ordering** — a named web can never sit above the temp
   band, and an SR base can never sit inside the named band (this is the func1C
   cd-base(48)/scanBase(46-47) wall, now proven structural, closing the investigation's open
   question). The only cross-band lever is CHANGING THE OBJECT'S IDENTITY:
   - **V-K absorption**: write the SR-candidate value as a named local's single-expression
     init so no `@` temp is created — the value numbers at the named decl position (validated
     in the doc: merged distRead kept named idx 46 → r23).
   - An ordinary-named temp (e.g. an inlined callee's local) numbers in band 3, BELOW all `@`
     temps — inlining-created values sit between user locals and SR clones.
5. **Eligibility gate**: `0x5e9c88[cls]` (physical regs remaining after params/precolors) must
   be > 0 (≥ 2 for pairs) at assign time, and the var must have desc+0x23=1 (IrOptimizer marks
   referenced candidates), desc+0x22=0 (CFunc creates locals with +0x22=1; the IroVars/IR-opt
   stage clears it for registerizable vars), and no volatile/address-taken flag.

For the walkgroup F40 interloper (idx 40, nadj 29, steals r22): idx 40 lies INSIDE the named
band → the interloper is a NAMED local (or ordinary-named temp), specifically the one with
exactly `top_index − 40` eligible locals declared after it. Count eligible decls from the top
of the decl list to identify it; then lever 1/2 moves it.

## 7. What the earlier notes got right/wrong (reconciliation)

- "Pop rule: params first, then strictly descending web index" — RIGHT (physical < base 34;
  Simplify pushes ascending-index, Select pops LIFO).
- "Named webs: decl order descending, contiguous band" — RIGHT, mechanism now proven.
- "SR temps appended", "base = named-band-top + 1 always" — RIGHT: band 4 head = last-created
  `@` temp.
- "Web NUMBERING is priority-driven (CodeGen_NumberWebs)" — WRONG for -O4: that family is the
  `0x5e9900==0` fallback. pri only gates band 5 (≥2) and eligibility (loop-pin 0x40 → 100000 is
  set but unused for ordering in virtual mode).
- "Numbering fires from the machine emission walk at 0x4c2932" — WRONG: stale stack slot (§0).
- "Commit order is NOT globally descending in pri (two interleaved worklists)" — explained: the
  bands are list-ordered, so pri sequences look arbitrary; the "two worklists" were bands 2/3/4.

## 8. Validation status & rerun recipe

Dynamic validation on this box is **blocked by a machine-level Rosetta wedge**: every fresh
x86_64 exec (wibo, fresh-inode copies, hash-perturbed copies, even a freshly clang-built
x86_64 hello) hangs in uninterruptible `U` state at exec; `arch -x86_64 /usr/bin/true`
(pre-cached Apple binary) works. Same syndrome family as the memory note
"build-contention-configure-deadlock"; likely needs an oahd/syspolicyd restart or reboot
(system settings — not touched). Static cross-validation instead: every recorded observation in
INVESTIGATION_dll14_residuals.md is reproduced by this model (§7), with zero contradictions.

Ready-to-run artifacts for when x86 exec recovers (all in scratchpad/webnum/):
- `wn_trace_lldb.py` — corrected tracer: logs cls/idx/pri/flags/obj/NAME plus the REAL caller
  (`ra2=[esp+56]` → site tags WL2/WL3/WL4/L_9d48/L_locals/L_tempA/L_tempB/L_978c, and
  `ra1=[esp+24]` which must always read 0x4d0556). Run:
  `lldb --batch -O 'command script import .../wn_trace_lldb.py' -O 'wn_trace_setup' -o run -- \
   build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe <cflags_base -lang=c> -c probe.c -o out/`
- `probe/probe_4regions.c` (decl order == first-use order) and `probe/probe_order.c` (init
  order permuted gamma,delta,beta,alpha vs decl alpha..i): identical `N cls=4` idx sequences
  for the named vars across both probes confirms decl-order (list) vs first-use; per-site tags
  directly confirm which band every commit is in, and whether L_9d48 stays silent (the one
  [inf] left).
- Disasm evidence: `webnum/caller_4c26.txt` (the refuted 0x4c29xx region),
  `webnum/commit_4fe4.txt` (commit fn + counter save/restore + reset),
  `webnum/codegen_numberwebs.txt` (worklists + in-order pass + driver fragment).

## 9. Key addresses (for follow-up sessions)

| VA | what |
|----|------|
| 0x4fe550 | commit: webIndex = webEnd[cls]++ (bp at 0x4fe563; real RA at [esp+24]) |
| 0x5e9b04[cls] | webEnd counters; 0x5e9800[cls] per-class base (GPR base = 34) |
| 0x5e9900 | virtual-mode flag (set by reset 0x4fe610; checked by driver 0x43361d) |
| 0x4d03a0 | classify+assign (only caller of commit); class gate 0x5e9c88[cls]>0 |
| 0x4d0150 | GetDesc (obj+0x2==1 → desc at obj+0x2a, else obj+0x32; desc size 0x2a) |
| 0x435d20 | THE in-order numbering pass (5 loops, 2 markers) |
| 0x435650/0x435810/0x435a10 | dead-for-us priority worklists (cls 2/3/4) |
| 0x5e9b00 / 0x5e99c4 / 0x5e9d48 / 0x5e978c | locals / temps / pre-scan / TOC lists (all head-prepend) |
| 0x4e9380 | temp-name predicate: name[0] ∈ {'@','$'} → band 4 |
| 0x4e91f0 | make_temporary_object (prepend when flag; '@N' namer at 0x4e49b5) |
| 0x4f0e15-0x4f0e4f | locals-list prepend (CFunc.c); alt branch dead (0x55ba70 ≡ 0) |
| 0x4dd650 / 0x4dd960 | per-function 0x5e9d48 builder / operand-chain walker |
| 0x4d0fe0 / 0x4d0ea0 | physical assign (params; budget 0x5e9c88[cls]--; no webEnd) |
| 0x4d01f0 / 0x4d0220 | band-boundary markers (locals-band start / temps-band end) |
