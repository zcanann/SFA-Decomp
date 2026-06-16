/*
 * DragonRock Palace perch switch (DLL 0x234; "DFP_PerchSw") - a legacy
 * object whose init/update are stubbed out: they only log
 * "<dfperchwitch Init>No Longer supported". The DLL also exports the
 * statue1 descriptor (gDfpstatue1ObjDescriptor) as a sibling object.
 */
#include "main/dll/crate2.h"

extern void OSReport(const char* fmt, ...);

int dfperchwitch_getExtraSize(void) { return 0x0; }
int dfperchwitch_getObjectTypeId(void) { return 0x0; }

void dfperchwitch_free(void)
{
}

void dfperchwitch_render(void)
{
}

void dfperchwitch_hitDetect(void)
{
}

void dfperchwitch_update(void) { OSReport(sDfperchwitchInitNoLongerSupported); }
void dfperchwitch_init(void) { OSReport(sDfperchwitchInitNoLongerSupported); }

void dfperchwitch_release(void)
{
}

void dfperchwitch_initialise(void)
{
}

ObjectDescriptor gDfpstatue1ObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfpstatue1_initialise,
    (ObjectDescriptorCallback)dfpstatue1_release,
    0,
    (ObjectDescriptorCallback)dfpstatue1_init,
    (ObjectDescriptorCallback)dfpstatue1_update,
    (ObjectDescriptorCallback)dfpstatue1_hitDetect,
    (ObjectDescriptorCallback)dfpstatue1_render,
    (ObjectDescriptorCallback)dfpstatue1_free,
    (ObjectDescriptorCallback)dfpstatue1_getObjectTypeId,
    dfpstatue1_getExtraSize,
};

ObjectDescriptor gDfperchwitchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfperchwitch_initialise,
    (ObjectDescriptorCallback)dfperchwitch_release,
    0,
    (ObjectDescriptorCallback)dfperchwitch_init,
    (ObjectDescriptorCallback)dfperchwitch_update,
    (ObjectDescriptorCallback)dfperchwitch_hitDetect,
    (ObjectDescriptorCallback)dfperchwitch_render,
    (ObjectDescriptorCallback)dfperchwitch_free,
    (ObjectDescriptorCallback)dfperchwitch_getObjectTypeId,
    dfperchwitch_getExtraSize,
};

char sDfperchwitchInitNoLongerSupported[] = "<dfperchwitch Init>No Longer supported \n";
