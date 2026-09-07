/*
 * Boot / loading-screen texture set: the Nintendo, Rareware and Dolby Pro Logic II
 * logos back-to-back, then 0xFF padding. The whole 0x40000 region is memcpy'd to
 * arena-top by videoInit() and reused as the GX FIFO after boot; initLoadingScreenTextures
 * reads the three texture records out of that arena copy. See docs/orig/embedded_assets.md
 * for the layout (Nintendo @ +0x0, Rareware @ +0x131E0, Dolby @ +0x1D240, pad @ +0x1F520).
 *
 * This is a copyrighted embedded asset and is never committed. dtk extracts
 * gLoadingScreenTextures from the user's own retail DOL at build time (config.yml
 * `extract:`), emitting a gitignored gLoadingScreenTextures.inc that we only #include here.
 */
#include "gLoadingScreenTextures.inc"

/* GPU diagnostics follow the FIFO-sized boot allocation. The error handlers
 * reach these strings relative to that allocation, so config retains their
 * individual symbols despite the absence of direct references. */
char sGpuHangSuspectedMessage[] = "Suspected graphics hang or infinite loop";
char sGpuHangStatusFormat[] = "GP status %d%d%d%d%d%d --> ";
char sGpuHangXfStallMessage[] = "GP hang due to XF stall bug.";
char sGpuHangUnterminatedMessage[] = "GP hang due to unterminated primitive";
char sGpuHangIllegalInstructionMessage[] = "GP hang due to illegal instruction.";
char sGpuHangWaitingMessage[] = "GP appears to be not hung (waiting for input).";
char sGpuHangUnknownMessage[] = "GP is in unknown state.";
char sGpuHangXfStallLog[] = "GP hang due to XF stall bug.\n";
char sGpuHangUnterminatedLog[] = "GP hang due to unterminated primitive.\n";
char sGpuHangIllegalInstructionLog[] = "GP hang due to illegal instruction.\n";
char sGpuHangWaitingLog[] = "GP appears to be not hung (waiting for input).\n";
char sGpuHangUnknownLog[] = "GP is in unknown state.\n";
