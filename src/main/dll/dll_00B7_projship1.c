/*
 * projship1 (DLL 0xB7) - retired "ship projectile 1" object.
 *
 * The object's behaviour was removed during development: its only live
 * entry point, projship1_doUnsupported, just logs a "no longer supported"
 * message and returns -1. release/initialise are empty lifecycle hooks
 * kept so the object descriptor / DLL loader still resolves.
 */
#include "main/dll/dll_72.h"
#include "main/engine_shared.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00B7_projship1.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void projwallpower_doUnsupported();
extern void projwallpower_release();
extern void projwallpower_initialise();

int projship1_doUnsupported(void)
{
    OSReport(sProjship1DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projship1_release(void)
{
}

void projship1_initialise(void)
{
}

char sProjship1DoNoLongerSupported[] = "<projship1 Do>No Longer supported \n";

DllDescriptorTable lbl_80319840 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projwallpower_initialise, projwallpower_release, (void*)0x00000000,
                                    projwallpower_doUnsupported}};
