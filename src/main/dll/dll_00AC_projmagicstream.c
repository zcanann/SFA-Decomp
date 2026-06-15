#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);




int projmagicstream_doUnsupported(void)
{
    OSReport(sProjmagicstreamDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projmagicstream_release(void)
{
}

void projmagicstream_initialise(void)
{
}



























