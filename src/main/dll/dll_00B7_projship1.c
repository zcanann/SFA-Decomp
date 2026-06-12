#include "main/dll/dll_72.h"

/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * early anonymous corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/dll_72.c
 * - 0x801008C4-0x801008C8
 *
 * Nearby corridor context:
 * - previous split: main/dll/dll_AF.c
 * - next split: main/dll/dll_73.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */

extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projship1_doUnsupported(void)
{
    OSReport(sProjship1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/*
 * --INFO--
 *
 * Function: projship1_release
 * EN v1.0 Address: 0x801008C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801008C8
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projship1_release(void)
{
}

/*
 * --INFO--
 *
 * Function: projship1_initialise
 * EN v1.0 Address: 0x801008CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801008CC
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projship1_initialise(void)
{
}
