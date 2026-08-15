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

int dll419_processAnimEvents(GameObject* unusedObj, int unusedArg, ObjSeqState* unusedAnimUpdate) {
    (void)unusedObj;
    (void)unusedArg;
    (void)unusedAnimUpdate;
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

void dll419_render(GameObject* unusedObj, int unusedArg2, int unusedArg3, int unusedArg4, int unusedArg5,
                   s8 unusedVisible) {
    (void)unusedObj;
    (void)unusedArg2;
    (void)unusedArg3;
    (void)unusedArg4;
    (void)unusedArg5;
    (void)unusedVisible;
}

void dll419_hitDetect(void) {
}

void dll419_update(GameObject* unusedObj) {
    (void)unusedObj;
}

void dll419_init(GameObject* obj) {
    obj->animEventCallback = dll419_processAnimEvents;
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
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
