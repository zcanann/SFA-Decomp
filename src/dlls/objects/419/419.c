/*
 * DLL 0x1A3 (slot 419) - a hidden object-group anchor.
 *
 * Instances join object group 0x3D. Slot 420 searches that group for an
 * object with the same placement pair ID, then follows its transform.
 */
#include "dlls/objects/419.h"
#include "game/objects/object.h"
#include "main/objseq.h"
#include "main/objtype.h"

int dll419_processAnimEvents(GameObject*, int, ObjSeqState*) {
    return 0;
}

int dll419_getExtraSize(void) {
    return 0;
}

int dll419_getObjectTypeId(void) {
    return 0;
}

void dll419_free(GameObject* obj) {
    objFreeObjectType(obj, DLL1A3_OBJECT_GROUP_ID);
}

void dll419_render(GameObject*, int, int, int, int, s8) {
}

void dll419_hitDetect(void) {
}

void dll419_update(GameObject*) {
}

void dll419_init(GameObject* obj) {
    obj->animEventCallback = dll419_processAnimEvents;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    objAddObjectType(obj, DLL1A3_OBJECT_GROUP_ID);
}

void dll419_release(void) {
}

void dll419_initialise(void) {
}

ObjectDescriptor gDll1A3ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll419_initialise,
    (ObjectDescriptorCallback)dll419_release,
    0,
    (ObjectDescriptorCallback)dll419_init,
    (ObjectDescriptorCallback)dll419_update,
    (ObjectDescriptorCallback)dll419_hitDetect,
    (ObjectDescriptorCallback)dll419_render,
    (ObjectDescriptorCallback)dll419_free,
    (ObjectDescriptorCallback)dll419_getObjectTypeId,
    dll419_getExtraSize,
};
