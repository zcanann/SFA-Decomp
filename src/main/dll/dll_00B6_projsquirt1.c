/*
 * projsquirt1 (DLL 0xB6) - retired "squirt" projectile object.
 *
 * The object's behaviour has been removed: its single live entry point
 * just logs that it is no longer supported and returns failure. The
 * release/initialise descriptor hooks are empty stubs.
 */
#include "dolphin/os.h"
#include "main/dll/dll_70.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

char sProjsquirt1DoNoLongerSupported[] = "<projsquirt1 Do>No Longer supported \n";

int projsquirt1_doUnsupported(void)
{
    OSReport(sProjsquirt1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projsquirt1_release(void)
{
}

void projsquirt1_initialise(void)
{
}
