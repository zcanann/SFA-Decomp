/*
 * projcore3 (DLL 0x00C1) - retired projectile-core variant.
 *
 * Every functional entry point has been stubbed out: the lone behavioural
 * hook, projcore3_doUnsupported, just logs the "no longer supported"
 * message and reports failure (-1). release/initialise are empty no-ops.
 * The DLL is kept as a placeholder so its slot/id remains valid.
 */
#include "dolphin/os.h"
#include "main/dll/modcloudrunner2.h"

int projcore3_doUnsupported(void)
{
    OSReport(sProjcore3DoNoLongerSupported);
    return -1;
}

void projcore3_release(void)
{
}

void projcore3_initialise(void)
{
}

char sProjcore3DoNoLongerSupported[] = "<projcore3 Do>No Longer supported \n";
