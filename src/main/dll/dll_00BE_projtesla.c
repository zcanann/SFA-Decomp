/*
 * projtesla (DLL 0xBE) - defunct "tesla" projectile (behaviour cut).
 *
 * Its only non-trivial entry point reports the "no longer supported" string
 * via OSReport and returns 0. The release and initialise descriptor hooks are
 * empty stubs.
 */
#include "main/dll/dll_7D.h"
#include "main/engine_shared.h"

extern void projcore1_doUnsupported(void);

extern void projcore1_release(void);

extern void projcore1_initialise(void);

int projtesla_doUnsupported(void)
{
    OSReport(sProjteslaDoNoLongerSupported);
    return 0;
}

void projtesla_release(void)
{
}

void projtesla_initialise(void)
{
}

char sProjteslaDoNoLongerSupported[] = "<projtesla Do>No Longer supported \n";

/* descriptor/ptr table auto 0x80319968-0x80319988.
 * Union u64 member forces the retail 8-byte alignment (table follows the
 * string, which ends 4-aligned; retail pads to an 8-aligned table start).
 * Same idiom as dll_00AD_projmagicemmit1 / dll_000A_expgfx. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_80319968 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projcore1_initialise, projcore1_release, (void*)0x00000000,
                                    projcore1_doUnsupported}};
