/*
 * projrobotfire (DLL 0x00B2) - the robot fire projectile object.
 *
 * The entire retail DLL is a stub: doUnsupported logs "no longer supported"
 * via OSReport and returns -1; release/initialise are empty.
 */
#include "dolphin/os.h"
#include "main/dll/dll_6D.h"

extern void projsquirt1_doUnsupported(void);

extern void projsquirt1_release(void);

extern void projsquirt1_initialise(void);

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projrobotfire_doUnsupported(void)
{
    OSReport(sProjrobotfireDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projrobotfire_release(void)
{
}

void projrobotfire_initialise(void)
{
}

char sProjrobotfireDoNoLongerSupported[] = "<projrobotfire Do>No Longer supported \n";

/* descriptor/ptr table auto 0x803197b0-0x803197d0 (8-byte aligned in retail;
 * pointer tables regenerate ADDR32 relocs). Union u64 member forces the
 * retail 8-byte alignment. Same idiom as dll_00B1_projlightning3. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

DllDescriptorTable lbl_803197B0 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projsquirt1_initialise, projsquirt1_release, (void*)0x00000000,
                                    projsquirt1_doUnsupported}};
