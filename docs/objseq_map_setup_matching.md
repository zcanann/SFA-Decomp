# ObjSeq_onMapSetup matching

`ObjSeq_onMapSetup` is **100% matching** in EN `GSAE01`, EN rev1, JP,
PAL, and PAL rev1. Each input DOL was verified against its configured hash
before comparison. The function is 760 bytes / 190 instructions in all five
versions. Resolving the EN source object's relocations at the retail addresses
also reproduces all 760 original DOL bytes exactly.

The source is now one ordinary loop over 85 slots, followed by seven global
resets. MWCC supplies the eight-slot unroll and the five-slot remainder.
This replaces the manually expanded bulk loop and pointer-based tail that
previously matched 99.947365%.

## Storage and language reconstruction

The final two instruction differences were consequences of how MWCC constructs
induction variables. LLDB backend traces showed that a native-array loop shares
the word-address temporary with the float-address virtual register, producing
the retail r10 allocation. The manually reconstructed tail used a separate
virtual register and selected r3.

Native arrays also exposed a storage problem. Under the C frontend, tentative
uninitialized definitions were allocated according to use and deferred-definition
order. Explicit zero initializers reproduced the registers but moved storage to
`.data`. Neither result preserved retail storage. A small independent two-array
compiler probe established that the C++ frontend instead supports the required
declaration-order BSS layout.

The complete, unsplit DLL now uses the common **GC/1.3** compiler in C++ mode,
with the existing optimization settings. `-bool off` retains the integer-valued
comparison results independently evidenced by the retail stream-stop stores
(`cntlzw`, `srwi`, `extsh`, `sth`) and the inlined NPC predicate. `-msext on`
accepts the existing anonymous structs in imported headers. C linkage preserves
the public ABI, and explicit pointer casts make the existing interfaces valid
under C++.

This is an evidence-backed language reconstruction, **not a recovered original
compiler command or proof that the original source was C++**. The evidence is
the native-array induction-variable topology, correct uninitialized storage,
and integer comparison widths, rather than aggregate match percentage alone.
The generated source path, compiler version, optimization profile, and TU
boundaries are unchanged. No inline assembly, per-function pragmas, initialized
BSS substitutes, or forced source sections are involved.

Six tables previously hidden in oversized declarations now have their own
85-element definitions:

| Table | Offset from runtime buffer | Element type |
| --- | ---: | --- |
| Slot marks | `0x338c` | `u8` |
| Slot object IDs | `0x33e4` | `int` |
| Slot distances | `0x3740` | `f32` |
| Pending frames | `0x39e8` | `s8` |
| Slot states | `0x3a40` | `u8` |
| Previous slot results | `0x3c4c` | `u8` |

The byte arrays have 85 elements; MWCC supplies the three alignment bytes.
Existing surrounding declarations retain their unexplained storage. EN symbol
boundaries record the recovered arrays without changing the TU's section ranges.
Small-data definitions are ordered to preserve every existing symbol address.

## Neighbouring functions and object audit

Using the native tables at the affected accesses preserves `ObjSeq_update`
exactly and improves `ObjSeq_start` from **98.89807% to 99.86226%**, reducing
it from 2,932 to the retail 2,904 bytes. Apart from `ObjSeq_start` and
`ObjSeq_onMapSetup`, every function retains its previous machine code.

All non-text section bytes, sizes, and alignments are unchanged. Existing
non-text symbols retain their offsets; the four oversized symbols shrink to
make room for the recovered tables. Data relocation destinations and addends
are unchanged. Text symbol offsets move with the shorter `ObjSeq_start`.
The complete DLL improves from **99.67799% to 99.76112%** and remains
`NonMatching`; the matching link still uses its retail object.

## Verification

`tools/objseq_map_setup_probe.py` executes the complete retail and source
functions in Unicorn PPC emulation. Expectations come from the retail stores,
independently of the reconstructed source: twelve tables across 85 slots,
seven globals, 1,027 writes, untouched padding and guards, and callee-preserved
registers. Four deterministic initial storage patterns pass.

With optional `unicorn` and `pyelftools` installed:

```sh
python3 tools/objseq_map_setup_probe.py --require-exact
```

`--require-exact` additionally resolves source data relocations at the EN TU's
retail addresses and compares all function bytes with the hash-verified DOL.
The former 99.947365% object correctly fails this check.

Validation: all five regional objdiff comparisons pass for the reset function;
`ninja all_source` passes; the strict EN build reports
`build/GSAE01/main.dol: OK`; and `clang-format --dry-run --Werror` passes for
the active TU. Formatting is committed separately and preserves the complete
source object's SHA-256.
