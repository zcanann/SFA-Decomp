# GPU hang diagnostics

SFA's `logGpuHang` and the on-screen diagnostics in `gpuErrorHandler` follow
Nintendo's DEMO hang diagnosis. Local reference copies of
`__DEMODiagnoseHang` in these files establish the counter interpretation:

- `reference_projects/ocarina_of_time_gc_port/src/dolphin/demo/DEMOInit.c`
- `reference_projects/super_mario_strikers/src/Dolphin/demo/DEMOInit.c`

The donors are evidence for the interpretation, not replacements for SFA's
bodies. SFA retains its log strings, screen output, callback state, diagnostic
thresholds, and exact control flow.

## Counter and status contract

The former `gxSetGPMetricsEnabled` name implied a general performance-monitor
switch. It is now `videoSetGpuHangMetricsEnabled`: the enabled path first
selects `GX_PERF0_NONE`/`GX_PERF1_NONE`, then writes the same diagnostic register
sequence as Nintendo's `DEMOSetGPHangMetric`. Its BP words are `2402C004` and
`23000020`; XF register `1006` receives `00084400`. Disable writes zero payloads
to those selectors. The retail low-byte test of the `int` argument is retained.
No FIFO commands or public argument types change.
The recovered source has no nonzero assignment to the zero-initialized
`gGpuHangRecoveryEnabled` flag. The normal enable path is therefore still
unidentified; this cleanup does not activate recovery or assume diagnostic
counters are configured before every status display.

With that configuration, the four `GXReadXfRasMetric` outputs are interpreted
as XF bottom, XF top, raster-ready, and setup-ready counters, in that argument
order. The old `topClks`/`botPerf0` names confused before/after sample order
with counter identity. Both SFA consumers now explicitly name before and after
samples, XF counters that did not change, and ready counters that advanced.
The unsigned subtractions preserve wraparound behavior.

`GXGetGPStatus`'s third output is FIFO-read idle and its fourth is command
idle, confirmed by the in-tree GX implementation reading CP status bits two
and three. These were called `cmdRdy` and `readIdle` in the reconstruction.
They now use `GXBool fifoReadIdle` and `GXBool commandIdle`. The unused outputs
still share one byte, and the logger retains its tested command-idle snapshot
assignment rather than changing register allocation for cosmetic uniformity.

The six printed bits consequently mean: FIFO-read idle, command idle, XF top
unchanged, XF bottom unchanged, setup-ready advanced, raster-ready advanced.
The existing ordered branches classify an XF stall, unterminated primitive,
illegal instruction, a GPU waiting for input, or unknown status. Neither the
classification order nor the diagnostic output changes.

## API ownership and validation

`include/main/gpu_hang.h` owns the metric selector, logger, and recovery-disable
API. The implementation and direct consumers include it instead of repeating
local prototypes or relying on the aggregate `pi_dolphin.h` header. The new selector
name is applied to its function symbol in EN, EN rev1, JP, and PAL rev1 without
changing any address or extent.

This is source and API recovery. All four verified versions preserve all function
instructions, allocated data, named-symbol layouts, and resolved relocations,
apart from the selector's symbol name. The recovered diagnostics remain exact.
No new constant-pool claim, TU split, compiler override, or inline assembly is
introduced. Existing boot-image-relative string accesses and video pool order
remain separate unresolved source/layout questions.

All four input DOL hashes and `all_source` builds pass, as does the strict EN
retail checksum. Complete objdiff reports are unchanged except for the selector
name. All 1,002 other EN source objects and 986 other source objects per secondary
target retain their raw hashes. Formatting is checked separately for object
identity in all four versions. No match-score gain is claimed.
