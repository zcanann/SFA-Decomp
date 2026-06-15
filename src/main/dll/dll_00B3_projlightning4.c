#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);






















int projlightning4_doUnsupported(void)
{
    OSReport(sProjlightning4DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning4_release(void)
{
}

void projlightning4_initialise(void)
{
}









