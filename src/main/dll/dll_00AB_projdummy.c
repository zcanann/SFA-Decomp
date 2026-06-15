#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);

int projdummy_doUnsupported(void)
{
    OSReport(sProjdummyDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projdummy_release(void)
{
}

void projdummy_initialise(void)
{
}






























