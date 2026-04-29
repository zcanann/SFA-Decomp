/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_80.c
 * - 0x801009DC-0x801009E0
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_7F.c
 * - next split: main/dll/dll_81.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char lbl_80319988[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
int fn_801009B0(void) { OSReport(lbl_80319988); return -1; }
#pragma scheduling reset
