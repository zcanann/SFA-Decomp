# Joint-matrix compiler audit

2026-09-06, EN v1.0. Follow-up to [the recovery and DTK investigation](joint_matrices.md).

The stock GC/1.3 compiler's ordinary C/C++ frame generator cannot produce the
retail entry's `stwu r1,-0xFC(r1)`. Its function-level assembler can produce
that frame, the internal `0x34` frame, private LR handling and paired-single
instructions together. This supports switching the *byte-matching strategy*
to assembly while retaining the recovered C as a behavior reference. It does
not establish whether Rare wrote assembly by hand, used assembly macros or
generation, mixed languages, or used an unexamined custom compiler.

No production source, compiler binary, flags, TU boundaries or matching
classification were changed for this audit. The assembly probe lives under
`build/` and is a small positive control, not a match of the complete function.

## Actual executable examined

`build/compilers/GC/1.3/mwcceppc.exe`, SHA-256:

```text
4e502c38465500d4fda8d966b268151a6c74c730508e3d9b7efd23d1a6083715
```

This was reverse-engineered from the installed PE executable with Ghidra
12.1.3 and checked against its x86 disassembly. Embedded assertion strings
identify compiler source units such as `StackFrame.c`, `Intrinsics.c` and
`FuncLevelAsmPPC.c`. Original compiler source was not available. The function
roles below are inferred names; the addresses and instructions are binary
observations. Addresses in this section are **compiler virtual addresses**,
not game addresses.

| Compiler address | Observed role |
| --- | --- |
| `0x00433590` | Ordinary code-generation pipeline; calls frame calculation at `0x004340C3`, then prologue generation |
| `0x004F7FB0` | Calculates frame layout; includes `StackFrame.c` assertion anchors |
| `0x004F82C7` | Rounds the allocated frame size to a multiple of 16 |
| `0x005DCCD6` | Frame-size storage consumed by the prologue emitter |
| `0x004F78C0` | Emits prologue and register saves |
| `0x004F7EB0` | Emits the stack update; normal branch uses the negative calculated frame size |
| `0x004C82F0` | Registers 315 intrinsic names |
| `0x00524400` | Function-level assembly pipeline; can bypass generated prologue/epilogue |

## Frame calculation is the strongest obstruction

The nonzero-frame path in `0x004F7FB0` reaches this x86 sequence:

```text
004F82C7  mov eax,[005DCCD6]
004F82CC  add eax,15
004F82CF  and eax,-16
004F82D2  sub eax,[005DCCD6]
004F82D8  add [005DCCD6],eax
```

Its effect is `frame_size = (frame_size + 15) & ~15`. Further alignment can
increase it. This rounding is unconditional within the allocated-frame path;
it is not guarded by the optimization level or struct-packing setting.
The zero-frame path does not explain a retail allocation of 252 bytes either.
The prologue emitter at `0x004F7EB0` takes this frame size and requests IR
opcode `0x32` (`stwu`) with register 1 as source/base and its negative as the
displacement. The alternative alignment path uses `stwux` and additional
instructions, unlike the retail entry.

Retail allocates 252 bytes at the outer entry and another 52 bytes at the
rotation helper. Neither is a multiple of 16, or even 8. This is a stronger
obstruction than a poor objdiff score or unusual register allocation. Changing
types, local lifetimes, helper inlining or DTK function boundaries does not
change this frame-generation rule.

Special stack operations were checked rather than assuming every `stwu` comes
from a C prologue:

- `__alloca(252)` is recognized. The probe first creates a normal 16-byte
  frame, then emits `stwu r0,-256(r1)` for the dynamic allocation. It does not
  reproduce the retail entry.
- `__rtos_change_stack` and `__rtos_pop_stack` are real registered intrinsics.
  The probe emits a normal frame plus a stack switch based on its supplied
  pointer. They do not create the observed internal helpers or entry frame.
- `__declspec(interrupt)` is accepted by GC/1.3. The tested interrupt function
  has a 336-byte frame and an interrupt epilogue, unlike retail.
- The function-level assembly path checks the no-frame flag at `0x005E7223`,
  clears the calculated frame through `0x004F5CF0`, and skips ordinary
  prologue/epilogue emission. The `nofralloc` control exercises this path.

These observations constrain stock code generation. They are not a formal
proof over every malformed program, compiler bug, postprocessor or modified
compiler, nor an exhaustive audit of every optimizer transformation.

## Nested definitions and instruction support

GC/1.3 rejects a GNU-style nested C function, computed goto, and both tested
`naked` spellings (`__declspec(naked)` and `__attribute__((naked))`).

C++ local classes **are supported**. With inlining disabled, a local static
method is emitted as a separate weak function symbol after the complete outer
function and called through an ordinary relocation. Its existence does not
explain retail's helpers embedded before the outer continuation, shared state,
`r29` return-address convention or shared outer exit.

The intrinsic initializer registers scalar operations such as `__fmadds`,
`__fsel`, `__cntlzw`, and the stack intrinsics above, plus AltiVec operations.
There are no `__psq_l`, `__psq_st`, `__ps_madds0` or `__mcrxr` registrations.
Calling these guessed names in C emits unresolved external calls. Positive
controls `__fmadds` and `__cntlzw` emit the expected instructions with no
external calls. The binary audit records all 315 registration names and their
addresses so this conclusion is not based only on guessing builtin names.

This does **not** mean MWCC cannot emit any paired-single instruction from C:
GC/1.3 can use `psq_st`/`psq_l` for nonvolatile floating-register preservation.
Also, finding `mcrxr` or paired-single mnemonics in the executable does not
establish a C lowering rule: they are supported assembler instructions.
The audit does not claim to have exhaustively classified every instruction
selector or opcode reference.

The isolated `asm void outer(void) { nofralloc ... }` control successfully
combines both retail frame sizes, `bl` to an internal label, LR saved/restored
through `r29`, `mcrxr`, `addme.`, a quantized load and paired-single arithmetic.
All three tested compiler versions accept it. This demonstrates that stock
MWCC can represent the troublesome shape through its assembler.

## Reproduction and results

With the project configured and its compiler/binutils dependencies available:

```sh
python3 tools/joint_matrices_compiler_probe.py
# Optional historical controls, without changing the project's compiler:
python3 tools/joint_matrices_compiler_probe.py \
    --compiler GC/1.3 --compiler GC/1.2.5 --compiler GC/1.3.2
```

The tool copies the configured render compile command into isolated probes,
replaces options explicitly, and records compiler hashes, full commands,
diagnostics, object hashes, symbol tables, disassembly and JSON under
`build/joint-matrices-compiler/probes/`. Its PE audit verifies the GC/1.3
rounding bytes and enumerates intrinsic registrations using only Python's
standard library. Ghidra is needed to repeat the deeper control-flow analysis,
not to run these checks. Other compiler hashes are reported as unmapped by the
static audit; their results below come from execution probes only.

Each compiler built 300 non-leaf C functions with local byte-array sizes 1–300
under seven settings: current render settings, `-O0`, `-O4,s`,
`ibm_stackframe on`, `-align mac68k`, `-align mac68k4byte`, and
`-use_lmw_stmw on`. The optimization variants retain unrelated render options,
including its `nopeephole,noschedule` setting. Packing and multiple-register
options need not change these simple functions; identical outputs are retained
in the results rather than treated as distinct generated shapes.

| Compiler | Tested C frames | GCD of frame sizes | Any `0xFC` or `0x34` frame? |
| --- | ---: | ---: | --- |
| GC/1.2.5 | 2,100 | 8 | No |
| GC/1.3 | 2,100 | 16 | No |
| GC/1.3.2 | 2,100 | 16 | No |

The older compiler's eight-byte frames are an actual version difference:
16-byte rounding should not be generalized to every MWCC release. They still
do not explain either retail frame. GC/1.2.5 also rejects the interrupt probe;
both later compilers accept it. All three reject the nested C, computed goto
and tested naked forms and emit the assembly positive control successfully.

The compile probes corroborate the binary analysis; their finite coverage is
not itself a proof that no other C program could have a particular shape.
DTK's `nocfa` experiment remains useful for representing and comparing this
region, but DTK cannot change MWCC's code-generation rules.

Validation after the audit: `ninja all_source` and the strict matching `ninja`
both exited 0 with `--joint-matrices-nocfa` enabled. DOL SHA-1 remains
`e750e8e894707a52446118a4b84f1b58b677b269`; the render object remains
`a7c8e9ed38da8549b1ada00aecab70b6be494867`. Objdiff still reports 15.515177%
similarity for this function. This audit adds evidence and tooling, not a
production byte-matching gain.
