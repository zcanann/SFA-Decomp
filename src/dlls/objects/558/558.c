/*
 * Ocean Force Point Temple door switch (DLL 0x22E) - a legacy/disabled object.
 * Every callback is either empty or logs
 * "<doorswitch Init>No Longer supported" via OSReport; the object holds no
 * extra state.
 */
#include "main/dll/DF/dll_022E_dfpdoorswitch.h"
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

ObjectDescriptor gDoorswitchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    doorswitch_initialise,
    doorswitch_release,
    0,
    doorswitch_init,
    doorswitch_update,
    doorswitch_hitDetect,
    doorswitch_render,
    doorswitch_free,
    (ObjectDescriptorCallback)doorswitch_getObjectTypeId,
    doorswitch_getExtraSize,
};

char sDoorswitchInitNoLongerSupported[] = "<doorswitch Init>No Longer supported \n";
