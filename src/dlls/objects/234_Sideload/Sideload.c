/*
 * Sideload object (DLL slot 234 / 0xEA).
 *
 * This deferred spawner creates Tricky once loading is unlocked, the player
 * exists, Tricky is absent, and the placement's arming game bit is set. The
 * spawned Tricky inherits the spawner's position and placement rotation.
 */
#include "dlls/objects/234_Sideload.h"
#include "main/gamebits_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define SIDELOAD_TRICKY_SEQ_ID 0x24
#define SIDELOAD_SETUP_FLAGS   5

void sideload_update(GameObject* obj) {
    SideloadPlacement* placement;
    ObjPlacement* setup;
    GameObject* tricky;

    placement = (SideloadPlacement*)obj->anim.placementData;
    if (Obj_CanSetupObject() != 0 && Obj_GetPlayerObject() != NULL && getTrickyObject() == NULL &&
        mainGetBit(placement->armingGameBit) != 0) {
        setup = Obj_AllocObjectSetup(sizeof(ObjPlacement), SIDELOAD_TRICKY_SEQ_ID);
        setup->loadFlags = 2;
        setup->mapActFlagsHi = 4;
        setup->unk07 = 0xFF;
        setup->posX = obj->anim.localPosX;
        setup->posY = obj->anim.localPosY;
        setup->posZ = obj->anim.localPosZ;
        tricky = objSetupObject(setup, SIDELOAD_SETUP_FLAGS, -1, -1, NULL);
        tricky->anim.rotX = (s16)(placement->childRotXByte << 8);
    }
}

ObjectDescriptor gSideloadObjDescriptor = {
    0,                                         /* reserved0 */
    0,                                         /* reserved1 */
    0,                                         /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,          /* slotCountAndFlags */
    0,                                         /* initialise */
    0,                                         /* release */
    0,                                         /* slot02 */
    0,                                         /* init */
    (ObjectDescriptorCallback)sideload_update, /* update */
    0,                                         /* hitDetect */
    0,                                         /* render */
    0,                                         /* free */
    0,                                         /* getObjectTypeId */
    0,                                         /* getExtraSize */
};
