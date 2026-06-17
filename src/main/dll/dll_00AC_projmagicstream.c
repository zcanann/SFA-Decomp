/*
 * projmagicstream (DLL 0xAC) - retired projectile object.
 *
 * One of the dll_66 family of stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "main/dll/dll_66.h"

/* declared here for codegen; not pulled in via dll_66.h */
extern void OSReport(const char* fmt, ...);

int projmagicstream_doUnsupported(void)
{
    OSReport(sProjmagicstreamDoNoLongerSupported);
    return -1; /* failure sentinel */
}

void projmagicstream_release(void)
{
}

void projmagicstream_initialise(void)
{
}
