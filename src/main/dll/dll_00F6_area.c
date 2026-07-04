/*
 * area (DLL 0xF6) - the trigger-area object class. A behaviourless
 * marker placed in a level: every per-frame callback (update / render /
 * hitDetect / free) is empty and it carries no extra state
 * (getExtraSize == 0). init() only stamps two bits (0xA000) into the
 * GameObject flag word; the object exists purely so the placement /
 * map-event system can reference an addressable region. Exported through
 * gAreaObjDescriptor with 10 callback slots.
 */
#include "main/object_descriptor.h"
#include "main/game_object.h"

#define AREA_OBJFLAG_UPDATE_DISABLED 0x8000
#define AREA_OBJFLAG_HITDETECT_DISABLED 0x2000

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

void area_init(GameObject* obj)
{
    obj->objectFlags = (u16)(obj->objectFlags | (AREA_OBJFLAG_UPDATE_DISABLED | AREA_OBJFLAG_HITDETECT_DISABLED));
}

void area_release(void)
{
}

void area_initialise(void)
{
}

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    area_initialise,
    area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};
