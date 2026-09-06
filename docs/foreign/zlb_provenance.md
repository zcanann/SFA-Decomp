# zlbDecompress provenance investigation, 2026-09-06

**Provenance remains unresolved.** Handwritten assembly, macro-generated code,
mixed C/assembly, and an unavailable or modified compiler remain hypotheses.
The evidence below weakens the specific stock-GCC attribution; it does not
establish that the whole function was handwritten. The old claim that `mcrxr`
proves GCC/SN ProDG provenance is withdrawn. The live reconstruction continues
to use ProDG 3.5 and remains `NonMatching`.

This investigation started at `e0cff4c0f6` and uses EN v1.0 retail, function
`0x8004B658..0x8004BF88` (2,352 bytes / 588 instructions). The DOL SHA-256 is
`466c2199e663df1e02a0a53569a2c36795b3f3e9fe061e458e8e2f34ce042b71`.

## Evidence that changes the diagnosis

1. **The proposed old-GCC signature is absent from old GCC.** Neither `rs6000.c`
   nor `rs6000.md` contains `mcrxr` in upstream GCC 2.7.2.3, 2.8.1, 2.95.2, or
   3.0. These are the target output routines and instruction descriptions, not
   just compiler manuals. None of the five installed ProDG `cc1.exe` binaries
   contains the ASCII mnemonic either. Those compilers emit textual assembly.
   `addme` does exist in GCC, notably in multi-instruction integer comparisons;
   that does not establish the retail decrement sequence as a GCC idiom.
   Sources: [GNU 2.7.2.3 release archive](https://ftp.gnu.org/gnu/gcc/gcc-2.7.2.3.tar.gz),
   [GCC 2.8.1 backend](https://github.com/gcc-mirror/gcc/blob/releases/gcc-2.8.1/gcc/config/rs6000/rs6000.md),
   [GCC 2.95.2 backend](https://github.com/gcc-mirror/gcc/blob/releases/gcc-2.95.2/gcc/config/rs6000/rs6000.md),
   [GCC 3.0 backend](https://github.com/gcc-mirror/gcc/blob/releases/gcc-3.0/gcc/config/rs6000/rs6000.md).

2. **Two assembly islands share a fingerprint across the entire executable.**
   Scanning the seven DOL text sections finds exactly 13 `mcrxr` instructions:
   two in zlb (`0x8004B708`, `0x8004BB80`) and eleven within the rendering unit's
   `0x80006C6C..0x80007F78` island. The only `stwu r1,-N(r1)` allocations whose
   size is not divisible by eight are:

   | Allocation instruction | Frame size | Location |
   | --- | ---: | --- |
   | `0x80006C70` | 252 (`0xFC`) | Rendering island entry |
   | `0x800072C8` | 52 (`0x34`) | Its internal subroutine |
   | `0x8004B65C` | 84 (`0x54`) | zlb entry |

   GCC's documented PowerPC EABI uses eight-byte stack alignment; its SysV
   alternative uses sixteen. Switching between them cannot explain these frames.
   [Contemporary GCC target-option documentation](https://gcc.gnu.org/onlinedocs/gcc-3.0.4/gcc_3.html)
   describes both conventions under `-meabi` / `-mno-eabi`.

3. **The rendering island supplies independent assembly evidence.** It branches
   with link to local labels and uses private register conventions: for example,
   `0x80006E34` saves LR in `r29`, calls the helper at `0x800072C4`, then restores
   LR from `r29` at `0x80007134`. Other helpers share live registers across their
   entry/return boundaries. This is not the ordinary C call topology surrounding
   the island. It concerns rendering/animation data, not an identified compressor.
   Sharing a macro or author is at least as plausible as sharing a C compiler.

4. **The zlb register and instruction choices resemble authored assembly.**
   Input remains in `r3`, output in `r5`; `r6` is unused. **Correction:** `r4` is
   repurposed for the code-length alphabet's maximum length, starting with
   `li r4,7` at `0x8004B91C`. The earlier claim that it stayed idle was wrong.
   Bit position, literal lengths/table/maxbits, distance
   lengths/table/maxbits, and rotate count occupy `r7,r8,r9,r10,r11,r12,r14,r15`.
   `r16..r19` recur as scratch registers in the bit-reader sequences. A leaf
   function saves LR despite having no calls. The 84-byte frame consists of the
   link area, one spilled final-block flag, and all 18 nonvolatile GPRs with no
   final ABI rounding. There are 24 `andi.` instructions, many with unused CR
   results, alongside explicitly selected rotate-and-mask operations.

5. **There is a dead comparison, not a conditional read.** At `0x8004B698`, retail
   compares bit position with six, but the following byte read/shift/OR are
   unconditional. The `andi.` at `0x8004B6B4` overwrites CR0 before any branch
   uses that comparison. Preserving a source ternary to manufacture the compare
   introduced branches that retail does not have. A leftover instruction after
   an assembly edit is a plausible explanation; its origin is not proven.

These observations do not exclude an unavailable proprietary backend, a modified
compiler, an assembler peephole pass, or inline assembly within a C TU. They do
exclude treating ordinary old GCC, a particular SN release, or a compiler-option
sweep as an already-established explanation. The retail DOL does not retain an
ELF `.comment` section or other compiler identification for this function.

## Actual compiler experiments

Same source for every row: the reconstruction at `e0cff4c0f6`, before this
investigation's two semantic corrections. ProDG's baseline flags are
`-O1 -fno-common -frerun-loop-opt -frerun-cse-after-loop`. MWCC uses GC/1.3,
the Gekko/PowerPC C ABI, and inline disabled; these are diagnostic profiles,
not an exhaustive MWCC search. The probe saves full flags and compiler hashes.

| Profile | Instructions | `stwu` frame | `mcrxr` | `andi.` | objdiff % |
| --- | ---: | ---: | ---: | ---: | ---: |
| Retail | 588 | 84 | 2 | 24 | 100 |
| ProDG 3.5 / 3.5b140 / 3.7 / 3.8.1 / 3.9.3 | 582 | 80 | 0 | 0 | 53.530613 |
| ProDG 3.5, also `-mno-update` | 590 | separate allocation | 0 | 0 | 52.596940 |
| ProDG 3.5, `-O0` | 1,336 | 184 | 0 | 0 | 0 |
| ProDG 3.5, `-O2` | 591 | 80 | 0 | 0 | 26.619047 |
| MWCC GC/1.3, `-O0` | 927 | 272 | 0 | 0 | 0 |
| MWCC GC/1.3, `-O1` | 724 | 64 | 0 | 0 | 27.726190 |
| MWCC GC/1.3, `-O4` | 645 | 80 | 0 | 0 | 17.518707 |

The five ProDG releases have the same instruction fingerprints and objdiff
score here. A zero fuzzy score means this comparison did not align usefully,
not that the emitted code has zero correct behavior. Disabling all update
addressing does not reproduce retail's selective use of `lbzu` / `stbu`.

## Could an external PowerPC compiler have supplied it?

Yes. This routine uses ordinary 32-bit integer PowerPC instructions, makes no
calls, and needs no GameCube-specific instruction support. A freestanding
big-endian PowerPC object can be linked into a GameCube program if its argument
and callee-save conventions, relocations, and global addressing agree with the
rest of the program. The compiler need not be marketed for GameCube. GCC already
supported generic embedded EABI targets, CPU selection, endian selection, and
small-data controls in this period; see the target-option documentation above.

That possibility does not explain the evidence by itself. A normal Linux/SysV
build still aligns the stack; a Mac/AIX object also raises object-format and
calling-convention issues. An assembly port or custom output pass is another
explanation for the observed irregularities; changing the advertised target
platform alone does not account for them.
The DKR/JFG reference projects contain assembly inflate implementations, which
supports investigating Rare's assembly lineage, but their bit-buffer/table
organization differs. This investigation did not establish a direct donor.
`source_leaks.py --search rarezip inflate` found no direct retail source clue.
`source_matrix.py` could not run because this checkout lacks its Rena debug-side
split dependency; no debug filename has been promoted to EN source truth.

## What would MWCC / ProDG need to change?

There is no demonstrated flag combination. A modified compiler would need to
explain **all** of the following, rather than force the two conspicuous opcodes:

- A decrement-and-test expansion using `mcrxr cr0; addme. rN,rN`. Clearing XER's
  carry makes `addme.` subtract one. Ordinary `addic.` can implement that
  decrement/test without this two-instruction sequence.
- The 84-byte frame and prologue/epilogue ordering, outside normal ABI rounding.
- Allocation that leaves `r6` idle while consuming nearly every nonvolatile
  GPR, and the recurring bit-reader scratch register choices.
- The exact mix of immediate masks, rotate masks, indexed loads, update forms,
  loop-address rematerialization, and a comparison whose result is dead.

Changing instruction-selection templates alone would leave the allocation,
scheduling, frame, and control-flow differences. Recreating a private assembly
macro convention is a more focused next experiment. An exact assembly
reconstruction should be reported as assembly recovery if that path is taken;
it would not establish that a C compiler was found or that the C matched.

## Source corrections and validation

- Removed the type-field ternary: retail loads the next byte unconditionally.
  The masked value is equivalent for valid bit positions, but the previous C
  added branches and omitted a retail read.
- Changed the stored-copy loop from `len-- != 0` to `--len != 0`. Retail clears
  carry, decrements, then branches on the new value. The previous reconstruction
  copied one extra byte. Its unusual overlapping halfword length reads remain
  intact; replacing them with a correct RFC1951 byte reader would change retail
  behavior and obscure a separate original bug.

Together these produce 577 instructions and **52.943880%**, down 0.586733
percentage points. All four data sections remain 100%. The unit stays
`NonMatching`, so the strict link still uses its retail object.

The optional Unicorn probe executes the complete retail and compiled functions.
It checks output, return value, and a 16-byte output canary for a stored-copy
witness plus actual BTYPE=1 and BTYPE=2 streams. Both new source and retail pass
all three. The pre-change object fails specifically by overwriting the stored
copy's canary; its fixed and dynamic cases pass. This is a bounded semantic
comparison, not an exhaustive stream test or a simulation of Gekko fault handling.
`ninja all_source` and the strict retail checksum target also pass.

## Partial inline assembly experiment

With the user's explicit authorization to try partial inline assembly, a small
retained change raises the function's objdiff score from **52.943880% to
57.977890%**. It adds four assembly instructions to `ZADV`, expanded at fourteen
call sites, plus local register bindings for the bit reader and table state.
All loops, Huffman construction, symbol decoding, copies, and entry/exit code
remain C/compiler generated. The arithmetic-only asm declares its inputs,
outputs, early-clobber scratch register, and condition-code clobber; it does
not access memory. The MWCC diagnostic path keeps the C macro.

The code-length alphabet now has its own `codeLengthMaxBits` local, distinct
from `literalMaxBits`, reflecting their separate retail registers (`r4` and
`r10`). This also exposed the incorrect idle-`r4` claim above. Register bindings
and the improved score are reconstruction choices, not compiler provenance.

Selected ProDG 3.5 experiments, with the existing optimization flags:

| Variant | Instructions | Frame | `mcrxr` | `andi.` | objdiff % |
| --- | ---: | ---: | ---: | ---: | ---: |
| Starting C | 577 | 80 | 0 | 1 | 52.943880 |
| Bit-advance asm, free register allocation | 584 | 80 | 0 | 15 | 55.241497 |
| Retained helper, register bindings, separate maximum lengths | 583 | 80 | 0 | 15 | 57.977890 |
| Prototype with custom entry/exit and stored-copy asm | 584 | 84 | 1 | 15 | 58.556120 |
| Retail | 588 | 84 | 2 | 24 | 100 |

The custom-frame prototype uses ProDG's accepted `__attribute__((naked))`, a
volatile final-block flag, and short assembly prologue/epilogue blocks. It can
emit the 84-byte frame without converting the decoder body to assembly. It
passes the same bounded emulation cases, but was not retained: C spills still
depend on the compiler's frame layout, and the improvement over the smaller
change is only 0.578230 percentage points. A future version would need an
explicit audit of every stack access after each compiler/source change.

Mask, rotate, and bit-peek asm helpers, other register subsets, and optimization
flags did not produce a large advance. The remaining mismatch includes loop
layout, pointer rematerialization, register allocation, and scheduling across
macro boundaries. For example, retail places `cmpwi` between the position mask
and shift-count update at `0x8004BA6C..0x8004BA74`; a four-instruction opaque
`ZADV` block prevents that exact interleaving. Merely forcing the conspicuous
opcodes and frame does not establish a full match. Further C restructuring may
help, but an exact match with only small asm islands has not been demonstrated.

All five installed ProDG releases compile the retained version to the same
instruction fingerprint and 57.977890% score. All four data sections remain
100%; the unit remains `NonMatching`. Formatting the source and owned header
does not change the instruction fingerprint or score. The emulator now checks
15 streams against both retail and source: stored, fixed, dynamic, empty,
single-byte, overlapping-copy, full-byte-alphabet, longer-distance, and
multi-block cases. Every run checks both output canaries, zero return value,
stack restoration, `r2`, `r13..r31`, and CR2-CR4 preservation. These checks pass
for both the retained version and the custom-frame prototype; they are not an
exhaustive DEFLATE or hardware-fault model.

The retained change also passes `ninja all_source`, the strict retail checksum
target, and `clang-format --dry-run --Werror` for the source and owned header.

## Typed Huffman Table Recovery

At `42e19e0dce`, the existing reconstruction was 583 instructions and
57.977890%. Recovering the literal decode pointer and active length-count
pointer as `u16*` removes their byte-offset arithmetic and repeated casts.
All three decode-table builders now use `table[nextCode[length]++]`, instead
of incrementing a temporary and then subtracting one from its index or the
table pointer. The code-length alphabet lookup takes the high `maxBits` bits
of its reversed byte with a right shift; its maximum is bounded to seven.

Together these C changes produce **584 instructions and 58.585033%**.
All four data sections and every data-symbol offset/size are unchanged.
No compiler flags, register bindings, or inline assembly were added or changed.
This remains a partial reconstruction, not a matched function or provenance
claim. The reconstructed object SHA-256 is
`c2a10429efc24ebef6fe9e7742e76c4102f552be3cdf1fcfae19d1fe69cd3a5f`.

The emulator now compares all 12 mutable Huffman arrays against retail after
each complete decode, using target-config symbol sizes and each image's own
addresses. All 15 streams pass output, canary, ABI, and table comparisons.
A scratch negative control toggles `gInflateLiteralNextCode[0]` just before
return: all 15 outputs remain correct, but all 15 source runs are rejected
specifically for the table mismatch. This controls the new check independently
of the output comparison. Stored-block quirks and the unresolved rotate/frame
provenance are unchanged.

## Reproduction

Configure/build in matching mode first, keeping each ninja invocation under the
runbook's 30-second timeout. Then:

```sh
python3 tools/zlb_provenance.py --compile --fetch-gcc
```

The default offline audit scans retail and installed compiler strings. The two
optional flags add compilation and upstream downloads. Output goes to
`build/zlb-provenance/`: JSON fingerprints, source/compiler/backend hashes,
compiler output, and a standalone objdiff project. To reproduce the historical
matrix, export `e0cff4c0f6:src/main/zlb.c` under `build/` and pass it with `--source`.
Compiler failures remain errors, never successful matches.

For semantic comparison, install the optional emulator into an isolated folder:

```sh
python3 -m pip install --target build/zlb-provenance/python-deps unicorn==2.1.4
PYTHONPATH=build/zlb-provenance/python-deps python3 tools/zlb_emulation_probe.py
```

`--object` can select another ProDG object for the negative control. Output is
written under `build/zlb-emulation/`; failed output/canary checks exit nonzero.
Neither tool changes source, compiler defaults, target symbols, or splits.
