/*
 * Area (DLL 0xF6) - inert area marker objects.
 *
 * Instances carry no extra state and disable both updates and hit detection.
 */
#include "dlls/objects/246_Area.h"
#include "game/objects/object.h"

int area_getExtraSize(void) {
    return 0;
}

int area_getObjectTypeId(void) {
    return 0;
}

void area_free(void) {
}

void area_render(void) {
}

void area_hitDetect(void) {
}

void area_update(void) {
}

void area_init(GameObject* obj) {
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_UPDATE_DISABLED | OBJECT_OBJFLAG_HITDETECT_DISABLED));
}

void area_release(void) {
}

void area_initialise(void) {
}

ObjectDescriptor gAreaObjDescriptor = {
    0,                                              /* reserved0 */
    0,                                              /* reserved1 */
    0,                                              /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,               /* slotCountAndFlags */
    (ObjectDescriptorCallback)area_initialise,      /* initialise */
    (ObjectDescriptorCallback)area_release,         /* release */
    0,                                              /* slot02 */
    (ObjectDescriptorCallback)area_init,            /* init */
    (ObjectDescriptorCallback)area_update,          /* update */
    (ObjectDescriptorCallback)area_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)area_render,          /* render */
    (ObjectDescriptorCallback)area_free,            /* free */
    (ObjectDescriptorCallback)area_getObjectTypeId, /* getObjectTypeId */
    area_getExtraSize,                              /* getExtraSize */
};
