/*
 * projlightning3 (DLL 0x00B1) - a retired projectile object.
 *
 * The lightning-3 projectile was cut from the shipped game: its object
 * entry point (projlightning3_doUnsupported) only logs that it is "no longer supported"
 * and returns the unsupported sentinel. release/initialise are the empty
 * object lifecycle hooks that remain so the object descriptor stays valid.
 */
#include "dolphin/os.h"
#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

char sProjlightning3DoNoLongerSupported[] = "<projlightning3 Do>No Longer supported \n";

int projlightning3_doUnsupported(void)
{
    OSReport(sProjlightning3DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning3_release(void)
{
}

void projlightning3_initialise(void)
{
}
