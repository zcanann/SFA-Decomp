/*
 * projrobotfire (DLL 0x00B2) - the robot fire projectile object.
 *
 * The entire retail DLL is a stub: doUnsupported logs "no longer supported"
 * via OSReport and returns -1; release/initialise are empty.
 */
#include "dolphin/os.h"
#include "main/dll/dll_6D.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projrobotfire_doUnsupported(void)
{
    OSReport(sProjrobotfireDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projrobotfire_release(void)
{
}

void projrobotfire_initialise(void)
{
}

char sProjrobotfireDoNoLongerSupported[] = "<projrobotfire Do>No Longer supported \n";
