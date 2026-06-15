#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);













int projlightning1_doUnsupported(void)
{
    OSReport(sProjlightning1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning1_release(void)
{
}

void projlightning1_initialise(void)
{
}


















