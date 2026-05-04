/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_7A.c
 * - 0x8010096C-0x80100970
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_79.c
 * - next split: main/dll/dll_7B.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */



extern char lbl_803198F8[];
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
int fn_80100940(void) { OSReport(lbl_803198F8); return -1; }
#pragma peephole reset
#pragma scheduling reset
