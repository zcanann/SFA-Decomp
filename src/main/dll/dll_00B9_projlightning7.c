#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);




























int projlightning7_doUnsupported(void)
{
    OSReport(sProjlightning7DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning7_release(void)
{
}

void projlightning7_initialise(void)
{
}



