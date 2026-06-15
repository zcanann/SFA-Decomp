#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);
















int projlightning2_doUnsupported(void)
{
    OSReport(sProjlightning2DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning2_release(void)
{
}

void projlightning2_initialise(void)
{
}















