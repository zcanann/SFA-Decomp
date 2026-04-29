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



extern char lbl_80319940[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
int fn_80100978(void) { OSReport(lbl_80319940); return 0; }
#pragma scheduling reset
