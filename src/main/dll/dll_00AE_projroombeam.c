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





















