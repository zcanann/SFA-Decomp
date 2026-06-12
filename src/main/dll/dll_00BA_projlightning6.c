#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);































int projlightning6_doUnsupported(void)
{
    OSReport(sProjlightning6DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning6_release(void)
{
}

void projlightning6_initialise(void)
{
}
