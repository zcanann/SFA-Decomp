/*
 * DragonRock Palace door switch (DLL 0x22E; "DFP_DoorSwitch", also DFPSpDA)
 * - a legacy/disabled object. Every callback is either empty or logs
 * "<doorswitch Init>No Longer supported" via OSReport; the object holds no
 * extra state.
 */
#include "main/dll/anim.h"
#include "main/engine_shared.h"

void doorswitch_render(void)
{
}

void doorswitch_hitDetect(void)
{
}

void doorswitch_release(void)
{
}

void doorswitch_initialise(void)
{
}

int doorswitch_getExtraSize(void) { return 0x0; }
int doorswitch_getObjectTypeId(void) { return 0x0; }

void doorswitch_free(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_update(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_init(void) { OSReport(sDoorswitchInitNoLongerSupported); }

char sDoorswitchInitNoLongerSupported[] = "<doorswitch Init>No Longer supported \n";

/* descriptor/ptr table auto 0x80329968-0x803299d8 */

ObjectDescriptor gDFP_seqpointObjDescriptor = {
    0x00000000, 0x00000000, 0x00000000,
    0x00090000,
    (ObjectDescriptorCallback)dfpseqpoint_initialise,
    (ObjectDescriptorCallback)dfpseqpoint_release,
    0x00000000,
    (ObjectDescriptorCallback)dfpseqpoint_init,
    (ObjectDescriptorCallback)dfpseqpoint_update,
    (ObjectDescriptorCallback)dfpseqpoint_hitDetect,
    (ObjectDescriptorCallback)dfpseqpoint_render,
    (ObjectDescriptorCallback)dfpseqpoint_free,
    (ObjectDescriptorCallback)dfpseqpoint_getObjectTypeId,
    dfpseqpoint_getExtraSize,
};
ObjectDescriptor gDFP_TorchObjDescriptor = {
    0x00000000, 0x00000000, 0x00000000,
    0x00090000,
    (ObjectDescriptorCallback)DFP_Torch_initialise,
    (ObjectDescriptorCallback)DFP_Torch_release,
    0x00000000,
    (ObjectDescriptorCallback)DFP_Torch_init,
    (ObjectDescriptorCallback)DFP_Torch_update,
    (ObjectDescriptorCallback)DFP_Torch_hitDetect,
    (ObjectDescriptorCallback)DFP_Torch_render,
    (ObjectDescriptorCallback)DFP_Torch_free,
    (ObjectDescriptorCallback)DFP_Torch_getObjectTypeId,
    DFP_Torch_getExtraSize,
};
