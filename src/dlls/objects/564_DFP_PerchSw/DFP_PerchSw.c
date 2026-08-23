/*
 * DragonRock Palace perch switch. This legacy object is no longer
 * supported; its init and update callbacks only report that fact.
 */
#include "main/dll/DF/dll_0234_dfperchwitch.h"
#include "dolphin/os/OSReport.h"

int dfperchwitch_getExtraSize(void)
{
    return 0x0;
}
int dfperchwitch_getObjectTypeId(void)
{
    return 0x0;
}

void dfperchwitch_free(void)
{
}

void dfperchwitch_render(void)
{
}

void dfperchwitch_hitDetect(void)
{
}

void dfperchwitch_update(void)
{
    OSReport(sDfperchwitchInitNoLongerSupported);
}
void dfperchwitch_init(void)
{
    OSReport(sDfperchwitchInitNoLongerSupported);
}

void dfperchwitch_release(void)
{
}

void dfperchwitch_initialise(void)
{
}

ObjectDescriptor gDfperchwitchObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dfperchwitch_initialise,
    dfperchwitch_release,
    0,
    dfperchwitch_init,
    dfperchwitch_update,
    dfperchwitch_hitDetect,
    dfperchwitch_render,
    dfperchwitch_free,
    (ObjectDescriptorCallback)dfperchwitch_getObjectTypeId,
    dfperchwitch_getExtraSize,
};

char sDfperchwitchInitNoLongerSupported[] = "<dfperchwitch Init>No Longer supported \n";
