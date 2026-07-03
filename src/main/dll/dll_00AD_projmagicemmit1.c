/*
 * projmagicemmit1 (DLL 0xAD) - retired projectile object.
 *
 * One of the dll_66 family of stubbed-out projectile DLLs. The object has
 * no behaviour left: release/initialise are empty and doUnsupported just
 * logs the "no longer supported" string and returns the failure sentinel.
 * The slot is kept so the DLL id stays valid.
 */
#include "main/dll/dll_66.h"
#include "main/engine_shared.h"

int projmagicemmit1_doUnsupported(void)
{
    OSReport(sProjmagicemmit1DoNoLongerSupported);
    return -1; /* failure sentinel */
}

void projmagicemmit1_release(void)
{
}

void projmagicemmit1_initialise(void)
{
}

char sProjmagicemmit1DoNoLongerSupported[] = "<projmagicemmit1 Do>No Longer supported \n";
