/*
 * DragonRock Palace perch switch (DLL 0x234; "DFP_PerchSw") - a legacy
 * object whose init/update are stubbed out: they only log
 * "<dfperchwitch Init>No Longer supported". The DLL also exports the
 * statue1 descriptor (gDfpstatue1ObjDescriptor) as a sibling object.
 */
#include "main/dll/crate2.h"
#include "main/engine_shared.h"

int DFP_PerchWitch_getExtraSize(void) { return 0x0; }
int DFP_PerchWitch_getObjectTypeId(void) { return 0x0; }

void DFP_PerchWitch_free(void)
{
}

void DFP_PerchWitch_render(void)
{
}

void DFP_PerchWitch_hitDetect(void)
{
}

void DFP_PerchWitch_update(void) { OSReport(sDfperchwitchInitNoLongerSupported); }
void DFP_PerchWitch_init(void) { OSReport(sDfperchwitchInitNoLongerSupported); }

void DFP_PerchWitch_release(void)
{
}

void DFP_PerchWitch_initialise(void)
{
}

ObjectDescriptor gDfpstatue1ObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFP_Statue1_initialise,
    (ObjectDescriptorCallback)DFP_Statue1_release,
    0,
    (ObjectDescriptorCallback)DFP_Statue1_init,
    (ObjectDescriptorCallback)DFP_Statue1_update,
    (ObjectDescriptorCallback)DFP_Statue1_hitDetect,
    (ObjectDescriptorCallback)DFP_Statue1_render,
    (ObjectDescriptorCallback)DFP_Statue1_free,
    (ObjectDescriptorCallback)DFP_Statue1_getObjectTypeId,
    DFP_Statue1_getExtraSize,
};

ObjectDescriptor gDfperchwitchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFP_PerchWitch_initialise,
    (ObjectDescriptorCallback)DFP_PerchWitch_release,
    0,
    (ObjectDescriptorCallback)DFP_PerchWitch_init,
    (ObjectDescriptorCallback)DFP_PerchWitch_update,
    (ObjectDescriptorCallback)DFP_PerchWitch_hitDetect,
    (ObjectDescriptorCallback)DFP_PerchWitch_render,
    (ObjectDescriptorCallback)DFP_PerchWitch_free,
    (ObjectDescriptorCallback)DFP_PerchWitch_getObjectTypeId,
    DFP_PerchWitch_getExtraSize,
};

char sDfperchwitchInitNoLongerSupported[] = "<dfperchwitch Init>No Longer supported \n";
