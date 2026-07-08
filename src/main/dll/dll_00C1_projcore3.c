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

/*__DATA_EXTERNS__*/
extern void projdfp1r_doUnsupported();
extern void projdfp1r_release();
extern void projdfp1r_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs).
 * Union u64 member forces the retail 8-byte alignment (table follows the
 * string, which ends 4-aligned; retail pads to an 8-aligned table start).
 * Same idiom as dll_00AD_projmagicemmit1 / dll_000A_expgfx. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_80319A40 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projdfp1r_initialise, projdfp1r_release, (void*)0x00000000,
                                    projdfp1r_doUnsupported}};
