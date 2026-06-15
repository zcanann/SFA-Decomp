#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);

























int projlightning5_doUnsupported(void)
{
    OSReport(sProjlightning5DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning5_release(void)
{
}

void projlightning5_initialise(void)
{
}






