/*
 * projcore2 (DLL 0xC0) - retired projectile-core DLL.
 *
 * The only live entry point reports that projectiles are no longer
 * supported and returns the unsupported sentinel (-1); the DLL's
 * release/initialise lifecycle hooks are empty stubs.
 */
#include "main/dll/dll_83.h"
#include "main/engine_shared.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projcore2_doUnsupported(void)
{
    OSReport(sProjcore2DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projcore2_release(void)
{
}

void projcore2_initialise(void)
{
}

char sProjcore2DoNoLongerSupported[] = "<projcore2 Do>No Longer supported \n";

extern void projcore3_initialise(void);
extern void projcore3_release(void);
extern int projcore3_doUnsupported(void);

/* projcore3 (DLL 0xC1) ResourceDescriptor, referenced by modelEngine.
 * Union u64 member forces the retail 8-byte alignment (table follows the
 * string, which ends 4-aligned; retail pads to an 8-aligned table start).
 * Same idiom as dll_00AD_projmagicemmit1 / dll_000A_expgfx. */
typedef union DllDescriptorTable {
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_803199F8 = { { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, projcore3_initialise, projcore3_release, (void*)0x00000000, projcore3_doUnsupported } };
