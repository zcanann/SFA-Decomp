/*
 * projcore1 (DLL 0xBF) - retired projectile-core DLL.
 *
 * The only live entry point reports that projectiles are no longer
 * supported and returns the unsupported sentinel (-1); the DLL's
 * release/initialise lifecycle hooks are empty stubs.
 */
#include "main/dll/dll_80.h"
#include "main/engine_shared.h"

int projcore1_doUnsupported(void)
{
    OSReport(sProjcore1DoNoLongerSupported);
    return -1;
}

void projcore1_release(void)
{
}

void projcore1_initialise(void)
{
}

char sProjcore1DoNoLongerSupported[] = "<projcore1 Do>No Longer supported \n";
