#include "main/dll/tFrameAnimator.h"
#include "main/game_object.h"

int area_getExtraSize(void) { return 0x0; }
int area_getObjectTypeId(void) { return 0x0; }

void area_free(void)
{
}

void area_render(void)
{
}

void area_hitDetect(void)
{
}

void area_update(void)
{
}

void area_init(u16* obj)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0xa000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

void area_release(void)
{
}

void area_initialise(void)
{
}

void levelname_free(void);

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)area_initialise,
    (ObjectDescriptorCallback)area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};
