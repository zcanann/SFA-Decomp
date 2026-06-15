#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);



















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












