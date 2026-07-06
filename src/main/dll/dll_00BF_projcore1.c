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

/*__DATA_EXTERNS__*/
extern void projcore2_doUnsupported();
extern void projcore2_release();
extern void projcore2_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs).
 * Union u64 member forces the retail 8-byte alignment (table follows the
 * string, which ends 4-aligned; retail pads to an 8-aligned table start).
 * Same idiom as dll_00AD_projmagicemmit1 / dll_000A_expgfx. */
typedef union DllDescriptorTable {
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_803199B0 = { { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projcore2_initialise, projcore2_release, (void*)0x00000000, projcore2_doUnsupported } };
