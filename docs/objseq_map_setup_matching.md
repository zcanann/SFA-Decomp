# ObjSeq_onMapSetup matching investigation

EN `GSAE01`, game GC/1.3 compiler, existing engine DLL 2 flags.
The function remains **99.210526%** matching: retail is 760 bytes and the
current source emits 764 bytes. No source or compiler settings were changed.

The first 135 instructions match. The remaining differences are eight register
operands in the tail and a duplicate byte store to `marks[0]`. The tail runs for
slots 80 through 84, so that instruction adds five writes without changing the
final memory contents.

Removing that duplicate store causes MWCC to unroll the tail again: the function
grows to 984 bytes. Indexed field accesses can keep the tail rolled, but tested
forms leave address calculations, different induction updates, or register
differences. A single automatically unrolled 85-slot pointer loop also differs:
its remainder advances twelve independent pointers; retail advances three and
derives the other nine addresses inside the tail.

A diagnostic single-iteration inner loop prevented the second unroll and
reproduced the 190-instruction shape, leaving the eight register differences.
It was discarded because the extra loop has no evidenced source-level purpose.
This isolates the unroll decision; it does not establish an acceptable source
reconstruction. LLDB backend capture was also used on an indexed-handle
candidate, which retained an extra address calculation.

## Reset oracle

`tools/objseq_map_setup_probe.py` executes the complete function in Unicorn PPC
emulation. It verifies the EN DOL against its configured hash before running.
The expectations come from the retail stores, independently of the source
overlay: twelve tables across 85 slots, seven globals, 1,027 writes, untouched
padding and guards, and callee-preserved registers.

Install the optional `unicorn` and `pyelftools` packages, then run:

```sh
python3 tools/objseq_map_setup_probe.py --retail-only
python3 tools/objseq_map_setup_probe.py --object path/to/candidate/2.o
```

Four deterministic initial storage patterns pass against retail. The candidate
with only the duplicate store removed also passes all four, despite its worse
assembly match. The unchanged source intentionally fails the strict write-count
check on five extra byte stores, one per tail slot; its final storage comparison
passes. The oracle supplements objdiff and does not establish an exact match.

Validation after restoring the source: a fresh compile of DLL 2 through
`ninja all_source` passes, and the strict retail checksum check reports
`build/GSAE01/main.dol: OK`.
