/*
 * projwallpower (DLL 0x00BB) - retired projectile "wall power" object.
 *
 * The object's behavior has been removed: the only live entry point,
 * projwallpower_doUnsupported, just reports that the feature is no longer
 * supported and returns 0 (false). release/initialise are empty lifecycle
 * stubs. sProjwallpowerDoNoLongerSupported is the message string (a data-only
 * extern resolved from the assembly data stub, declared in dll_64.h).
 *
 * Note: unlike the rest of the retired-projectile family (projlightning1,
 * projquakeshock, etc.) which return the -1 unsupported sentinel, wallpower
 * returns 0.
 */
#include "main/dll/dll_64.h"
#include "main/engine_shared.h"

int projwallpower_doUnsupported(void)
{
    OSReport(sProjwallpowerDoNoLongerSupported);
    return 0;
}

void projwallpower_release(void)
{
}

void projwallpower_initialise(void)
{
}

char sProjwallpowerDoNoLongerSupported[] = "<projwallpower Do>No Longer supported \n";

/*__DATA_EXTERNS__*/
extern void projquakeshock_doUnsupported();
extern void projquakeshock_release();
extern void projquakeshock_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80319888[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projquakeshock_initialise, projquakeshock_release, (void*)0x00000000, projquakeshock_doUnsupported };
