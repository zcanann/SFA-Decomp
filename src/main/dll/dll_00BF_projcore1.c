#include "main/dll/dll_80.h"

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


extern void OSReport(const char* fmt, ...);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projcore1_doUnsupported(void)
{
    OSReport(sProjcore1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

/* === merged from main/dll/dll_81.c [801009E0-801009E4) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/dll_81.h"

/*
 * --INFO--
 *
 * Function: projcore1_release
 * EN v1.0 Address: 0x801009E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801009E0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projcore1_release(void)
{
}

/* === merged from main/dll/dll_82.c [801009E4-801009E8) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/dll_82.h"

/*
 * --INFO--
 *
 * Function: projcore1_initialise
 * EN v1.0 Address: 0x801009E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801009E4
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void projcore1_initialise(void)
{
}
