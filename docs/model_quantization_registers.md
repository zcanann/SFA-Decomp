# Model quantization register recovery

`setGQR6` and `setGQR7` now write the actual hardware registers. Previously,
the first was empty and the second stored into an invented `sGQR7Config`
variable. The three scalar vertex reconstructions now read GQR7 through a
private inline accessor, so the fabricated variable is no longer needed.

This is the narrow hardware-access exception recorded in `AGENTS.md`, using
the active goal's explicit allowance for compelling evidence. It does not
replace the scalar vertex arithmetic with assembly or establish that those
reconstructions are equivalent to the retail paired-single kernels.

## Evidence and scope

EN retail `setGQR6` at `8002A3C4` is exactly `mtspr GQR6,r3; blr`.
`setGQR7` at `8002A3CC` is exactly `mtspr GQR7,r3; blr`. There is no RAM store.
The following two C wrappers pack the load scale/type in the upper halfword
and the store scale/type in the lower halfword. Their argument names now
express those roles; the arithmetic and generated instructions are unchanged.

`ObjModel_InitRenderBuffers` configures GQR6 with `(7,4,7,4)`.
The normal and vertex stream wrappers configure GQR7 from the job's
quantization shift, with types 6 and 7 respectively. Retail kernels load
weights through paired-single accesses using GQR6, and load/store vertex
components through GQR7. The register writes are therefore real dependencies,
not discarded computations. The existing scalar kernels still use their
approximate conversion/arithmetic implementations; only their source of
quantization state changes.

The SDK's `OSContext.c` also saves and restores these registers. A process-wide
RAM shadow cannot represent that context-owned state. Reading GQR7 directly
removes this inconsistency without hard-coding a scale or adding a synthetic
storage slot. The private getter is a reconstruction aid, not a newly claimed
retail function.

The active GC/1.3 compiler compiles candidate `__mtspr` and `__mfspr` spellings
as unresolved function calls, not intrinsic instructions. There is no usable
operation in the current headers for these GQR accesses. Wind Waker's local
`src/JSystem/J3DGraphBase/J3DTransform.cpp` provides a contemporary analogue:
`__MTGQR7` uses one inline `mtspr`, and `J3DGQRSetup7` uses the same four-argument
packing expression. This supports the source form, not a claim that SFA used
J3D or that the neighboring kernels came from that project.

The exception covers one special-register instruction in each of the two
setters and the inline reader. No compiler profile, translation-unit boundary,
matching status, or checksum expectation changes.

## Object and behavior checks

The new setters are byte-exact retail functions. Each scalar kernel gains one
live GQR7 read in place of its old shadow access; its size and remaining
arithmetic stay unchanged. All other function bodies, including the two packing
wrappers, remain byte-identical. Relocations are compared by function-relative
source positions and resolved target identities, accounting for the four-byte
increase in the first setter's size.

The only removed data symbol is the invented shadow at source `.sbss+36`.
Every other named data offset is unchanged. Source `.sbss` shrinks from 40 to
36 bytes; the existing 40-byte EN retail claim includes the following alignment
space. Other allocated data sections remain unchanged, and objdiff's matched
data count does not increase.

Existing model tests cover 22 blend-channel passes, 144 matrix-preparation
scenarios and 135 sparse morph scenarios at each of host `-O0` and `-O2`.
The morph emulator additionally runs 16 decoder cases and 135 morph scenarios
against both compiled and retail instructions, including private ABI checks.
These checks protect the surrounding recovery; they do not emulate Gekko
quantization hardware or prove the scalar kernels match retail numerically.

## Cross-version results

All four inputs pass their configured retail SHA-1. The setters match their
retail bytes directly, and the normalized instruction signatures of the three
kernels, two packing wrappers, render-buffer initializer and two stream
wrappers agree across versions. Each version gains two exact functions and
16 matched code bytes. No other scored function changes.

| Version | GQR6 setter | GQR7 setter | `all_source` seconds |
| --- | --- | --- | --- |
| GSAE01 | `0x8002a3c4` | `0x8002a3cc` | 19.50 |
| GSAE01_rev1 | `0x8002a49c` | `0x8002a4a4` | 19.57 |
| GSAJ01 | `0x8002a3c4` | `0x8002a3cc` | 20.04 |
| GSAP01_rev1 | `0x8002a538` | `0x8002a540` | 21.38 |

All four source objects have SHA-256
`4dd73ccd830d58b07cbd2a273a322c695ccc9f3ccac2da164a9680d657e0da13`.
The active model source/header pass the formatter check without changes.
PAL revision 0 remains excluded because the local file fails its configured
retail hash.

Final EN `all_source` and strict checksum builds pass in 21.13
and 30.01 seconds. The linked DOL retains SHA-1
`e750e8e894707a52446118a4b84f1b58b677b269`.
