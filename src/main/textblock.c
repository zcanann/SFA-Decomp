#include "dolphin/os.h"
#include "main/textblock.h"

int textblockObj_getExtraSize(void)
{
    return 0;
}

int textblockObj_getObjectTypeId(void)
{
    return 0;
}

void textblockObj_freeUnsupported(void)
{
    OSReport(sTextBlockObjInitNoLongerSupported);
    return;
}

void textblockObj_render(void)
{
}

void textblockObj_hitDetect(void)
{
}

void textblockObj_updateUnsupported(void)
{
    OSReport(sTextBlockObjInitNoLongerSupported);
    return;
}

void textblockObj_init(void)
{
    OSReport(sTextBlockObjInitNoLongerSupported);
    return;
}

void textblockObj_release(void)
{
}

void textblockObj_initialise(void)
{
}

ObjectDescriptor gTextBlockObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    textblockObj_initialise,
    textblockObj_release,
    0,
    textblockObj_init,
    textblockObj_updateUnsupported,
    textblockObj_hitDetect,
    textblockObj_render,
    textblockObj_freeUnsupported,
    (ObjectDescriptorCallback)textblockObj_getObjectTypeId,
    textblockObj_getExtraSize,
};

char sTextBlockObjInitNoLongerSupported[] = "<textblock.c Init>No Longer supported \n";
