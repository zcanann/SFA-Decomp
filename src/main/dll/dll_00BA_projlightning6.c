/*
 * projlightning6 (DLL 0xBA) - retired lightning-projectile object.
 *
 * Only a deprecation stub survives: the object's main entry point logs
 * "no longer supported" and returns the unsupported sentinel; release and
 * initialise are empty. The behaviour was removed before retail, so the
 * DLL exists purely to keep the object id slot wired up.
 */
#include "main/dll/dll_66.h"
#include "main/engine_shared.h"
#include "main/dll/dll_descriptor_table.h"
#include "main/dll/dll_00BA_projlightning6.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void projenergise1_doUnsupported(void);
extern void projenergise1_release(void);
extern void projenergise1_initialise(void);

int projlightning6_doUnsupported(void)
{
    OSReport(sProjlightning6DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning6_release(void)
{
}

void projlightning6_initialise(void)
{
}

char sProjlightning6DoNoLongerSupported[] = "<projlightning6 Do>No Longer supported \n";

DllDescriptorTable lbl_803196D8 = {{(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                                    projenergise1_initialise, projenergise1_release, (void*)0x00000000,
                                    projenergise1_doUnsupported}};
