/*
 * projgfx (DLL 0x0C) - model-graphics / preset-particle effect support.
 *
 * projgfx_funcs is the object's ObjectDescriptor11; most slots are no-ops or
 * "No Longer supported" OSReport stubs (release/rayhit/setzscale).
 */
#include "main/dll/modgfx.h"
#include "main/game_object.h"
#include "main/sfa_shared_decls.h"

#define PROJGFX_UNSUPPORTED_FALSE_RETURN 0

void projgfx_func07_nop(void)
{
}

void projgfx_func06_nop(void)
{
}

void projgfx_func05_nop(void)
{
}

void projgfx_onMapSetup(void)
{
}

void projgfx_initialise(void)
{
}

int projgfx_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
void projgfx_release_doUnsupported(void) { OSReport(sProjgfxReleaseDoNoLongerSupported); }
#pragma scheduling reset

#pragma scheduling off
int projgfx_rayhit_doUnsupported(void)
{
    OSReport(sProjgfxRayhitDoNoLongerSupported);
    return PROJGFX_UNSUPPORTED_FALSE_RETURN;
}

int projgfx_setzscale_doUnsupported(void)
{
    OSReport(sProjgfxSetzscaleDoNoLongerSupported);
    return PROJGFX_UNSUPPORTED_FALSE_RETURN;
}
#pragma scheduling reset

int projgfx_func04_ret_m1(void) { return -0x1; }

ObjectDescriptor11 projgfx_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    projgfx_initialise,
    (ObjectDescriptorCallback)projgfx_release_doUnsupported,
    0,
    projgfx_onMapSetup,
    (ObjectDescriptorCallback)projgfx_func04_ret_m1,
    (ObjectDescriptorCallback)projgfx_func05_nop,
    (ObjectDescriptorCallback)projgfx_func06_nop,
    (ObjectDescriptorCallback)projgfx_func07_nop,
    (ObjectDescriptorCallback)projgfx_getObjectTypeId,
    (ObjectDescriptorCallback)projgfx_setzscale_doUnsupported,
    (ObjectDescriptorCallback)projgfx_rayhit_doUnsupported,
};

char sProjgfxRayhitDoNoLongerSupported[] = "<projgfx rayhit Do>No Longer supported \n";
static u8 sProjgfxStringPad0[] = {0, 0, 0};
char sProjgfxSetzscaleDoNoLongerSupported[] = "<projgfx setzscale  Do>No Longer supported \n";
static u8 sProjgfxStringPad1[] = {0, 0, 0};
char sProjgfxReleaseDoNoLongerSupported[] = "<projgfx release Do>No Longer supported \n";
static u8 sProjgfxStringPad2[] = {0, 0, 0, 0, 0, 0};
