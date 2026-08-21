/*
 * Side-repel object family (DLL slot 235 / 0xEB).
 *
 * These invisible, non-updating volumes register with the side-repel object
 * group used by Tricky. Their hit-sphere radius is one eighth of the
 * placement radius.
 */
#include "dlls/objects/235.h"
#include "main/objhits.h"
#include "main/objtype.h"

#define SIDEREPEL_OBJECT_GROUP 0x40
#define SIDEREPEL_RADIUS_SHIFT 3

int siderepel_getExtraSize(void) {
    return sizeof(SideRepelState);
}

void siderepel_free(GameObject* obj) {
    objFreeObjectType(obj, SIDEREPEL_OBJECT_GROUP);
}

void siderepel_init(GameObject* obj, SideRepelPlacement* placement) {
    obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED | OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    objAddObjectType(obj, SIDEREPEL_OBJECT_GROUP);
    if (obj->anim.hitReactState != NULL) {
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                  (s16)(placement->minDistance >> SIDEREPEL_RADIUS_SHIFT));
    }
}

ObjectDescriptor gSiderepelObjDescriptor = {
    0,                                        /* reserved0 */
    0,                                        /* reserved1 */
    0,                                        /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,         /* slotCountAndFlags */
    0,                                        /* initialise */
    0,                                        /* release */
    0,                                        /* slot02 */
    (ObjectDescriptorCallback)siderepel_init, /* init */
    0,                                        /* update */
    0,                                        /* hitDetect */
    0,                                        /* render */
    (ObjectDescriptorCallback)siderepel_free, /* free */
    0,                                        /* getObjectTypeId */
    siderepel_getExtraSize,                   /* getExtraSize */
};
