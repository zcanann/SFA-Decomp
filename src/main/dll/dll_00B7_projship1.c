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

#define PROJECTILE_UNSUPPORTED_RETURN -1

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

/*__DATA_EXTERNS__*/
extern void projwallpower_doUnsupported();
extern void projwallpower_release();
extern void projwallpower_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs).
 * Union u64 member forces the retail 8-byte alignment after the 0x24-byte
 * string (retail pad gap_07_8031983C_data). Same idiom as
 * dll_00B1_projlightning3. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_80319840 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projwallpower_initialise, projwallpower_release, (void*)0x00000000,
                                    projwallpower_doUnsupported}};
