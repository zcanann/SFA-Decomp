/*
 * projroombeam (DLL 0xAE) - retired projectile object.
 *
 * One of the dll_66 family of stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);

int projroombeam_doUnsupported(void)
{
    OSReport(sProjroombeamDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projroombeam_release(void)
{
}

void projroombeam_initialise(void)
{
}
