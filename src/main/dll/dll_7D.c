/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_7D.c
 * - 0x801009A4-0x801009A8
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_7C.c
 * - next split: main/dll/dll_7E.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char sProjteslaDoNoLongerSupported[];
extern void OSReport(const char *fmt, ...);

#define PROJECTILE_UNSUPPORTED_FALSE_RETURN 0

#pragma scheduling off
#pragma peephole off
int projtesla_doUnsupported(void) { OSReport(sProjteslaDoNoLongerSupported); return PROJECTILE_UNSUPPORTED_FALSE_RETURN; }
#pragma peephole reset
#pragma scheduling reset
