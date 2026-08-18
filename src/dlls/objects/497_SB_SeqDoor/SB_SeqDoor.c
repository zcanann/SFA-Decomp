/* SB_SeqDoor (DLL 0x01F1) - a sequence-controlled Ship Battle door. */
#include "dlls/objects/497_SB_SeqDoor.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objseq.h"

#define SB_SEQDOOR_SEQ_ID 0x173

int SB_SeqDoor_SeqFn(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    if (obj->anim.romDefNo != SB_SEQDOOR_SEQ_ID) {
        animUpdate->flags = -2;
    }
    animUpdate->movementState = 0;
    return 0;
}

int SB_SeqDoor_getExtraSize(void) {
    return 0;
}

int SB_SeqDoor_getObjectTypeId(void) {
    return 0;
}

void SB_SeqDoor_free(void) {
}

void SB_SeqDoor_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible == 0) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void SB_SeqDoor_hitDetect(void) {
}

void SB_SeqDoor_update(GameObject* obj) {
    if (obj->anim.romDefNo == SB_SEQDOOR_SEQ_ID && obj->userData1 == 0 && mainGetBit(GAMEBIT_SB_DoorOpen) != 0) {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        obj->userData1 = 1;
    }
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
}

void SB_SeqDoor_init(GameObject* obj, const SBSeqDoorPlacementView* placement) {
    obj->animEventCallback = SB_SeqDoor_SeqFn;
    obj->anim.rotX = placement->rotXByte << 8;
    obj->anim.bankIndex = placement->bankSelect != 0;
}

void SB_SeqDoor_release(void) {
}

void SB_SeqDoor_initialise(void) {
}

ObjectDescriptor gSB_SeqDoorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SB_SeqDoor_initialise,
    SB_SeqDoor_release,
    0,
    (ObjectDescriptorCallback)SB_SeqDoor_init,
    (ObjectDescriptorCallback)SB_SeqDoor_update,
    SB_SeqDoor_hitDetect,
    (ObjectDescriptorCallback)SB_SeqDoor_render,
    SB_SeqDoor_free,
    (ObjectDescriptorCallback)SB_SeqDoor_getObjectTypeId,
    SB_SeqDoor_getExtraSize,
};
