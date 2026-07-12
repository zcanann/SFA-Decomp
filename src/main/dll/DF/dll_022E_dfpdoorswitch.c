/*
 * DragonRock Palace door switch (DLL 0x22E; "DFP_DoorSwitch", also DFPSpDA)
 * - a legacy/disabled object. Every callback is either empty or logs
 * "<doorswitch Init>No Longer supported" via OSReport; the object holds no
 * extra state.
 */
#include "main/dll/anim.h"
#include "dolphin/os/OSReport.h"

int doorswitch_getExtraSize(void)
{
    return 0x0;
}
int doorswitch_getObjectTypeId(void)
{
    return 0x0;
}

void doorswitch_free(void)
{
    OSReport(sDoorswitchInitNoLongerSupported);
}

void doorswitch_render(void)
{
}

void doorswitch_hitDetect(void)
{
}

void doorswitch_update(void)
{
    OSReport(sDoorswitchInitNoLongerSupported);
}
void doorswitch_init(void)
{
    OSReport(sDoorswitchInitNoLongerSupported);
}

void doorswitch_release(void)
{
}

void doorswitch_initialise(void)
{
}

char sDoorswitchInitNoLongerSupported[] = "<doorswitch Init>No Longer supported \n";

ObjectDescriptor gDFP_seqpointObjDescriptor = {
    0x00000000,
    0x00000000,
    0x00000000,
    0x00090000,
    (ObjectDescriptorCallback)DFP_seqpoint_initialise,
    (ObjectDescriptorCallback)DFP_seqpoint_release,
    0x00000000,
    (ObjectDescriptorCallback)DFP_seqpoint_init,
    (ObjectDescriptorCallback)DFP_seqpoint_update,
    (ObjectDescriptorCallback)DFP_seqpoint_hitDetect,
    (ObjectDescriptorCallback)DFP_seqpoint_render,
    (ObjectDescriptorCallback)DFP_seqpoint_free,
    (ObjectDescriptorCallback)DFP_seqpoint_getObjectTypeId,
    DFP_seqpoint_getExtraSize,
};
ObjectDescriptor gDFP_TorchObjDescriptor = {
    0x00000000,
    0x00000000,
    0x00000000,
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
