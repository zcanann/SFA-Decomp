/*
 * MMSH_Scales (DLL 0x18D) advances object-trigger sequences and spawns the
 * scalessword child used by the Moon Mountain Pass sequence.
 */
#include "dlls/objects/397_MMSH_Scales.h"

#include "dlls/objects/298_CFCrate.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#include "main/frame_timing.h"
#include "main/objseq.h"
#define MMSH_SCALES_OBJECT_TYPE_ID          0xB
#define MMSH_SCALES_CLASS_ID                0x10
#define MMSH_SCALES_CHILD_SETUP_FLAGS       5
#define MMSH_SCALES_CHILD_COLOR_RED         0x20
#define MMSH_SCALES_CHILD_COLOR_GREEN       0x04
#define MMSH_SCALES_CHILD_COLOR_ALPHA       0xFF
#define MMSH_SCALES_CHILD_SCALE             2.0f
#define MMSH_SCALES_RENDER_SCALE            1.0f
#define MMSH_SCALES_SEQUENCE_PENDING        -2
#define MMSH_SCALES_SEQUENCE_NONE           -1
#define MMSH_SCALES_SEQUENCE_FLAGS          -1
#define MMSH_SCALES_CURVE_NONE              -1
#define MMSH_SCALES_ANIM_DATA_NONE          -1
#define MMSH_SCALES_DEFAULT_ANIM_DATA_INDEX 1
#define MMSH_SCALES_NO_MAP_LAYER            -1
#define MMSH_SCALES_NO_OBJECT_INDEX         -1


int mmshScales_getExtraSize(void) {
    return sizeof(MMSHScalesState);
}

int mmshScales_getObjectTypeId(void) {
    return MMSH_SCALES_OBJECT_TYPE_ID;
}

void mmshScales_free(GameObject* obj, int keepChild) {
    GameObject* child;

    (*gObjectTriggerInterface)->freeState(obj->extra);
    gTitleMenuControlInterfaceCopy->vtable->func05(obj, 0xffff, 0, 0, 0);
    child = obj->childObjs[0];
    if (child != NULL && keepChild == 0) {
        Obj_FreeObject(child);
    }
}

void mmshScales_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, MMSH_SCALES_RENDER_SCALE);
    }
}

void mmshScales_hitDetect(void) {
}

void mmshScales_update(GameObject* obj) {
    int slot;
    GameObject** objects;
    GameObject* otherObj;
    GameObject* sequenceOwner;
    int groupSlot;
    int siblingCount;
    int objectIndex;
    int objectCount;

    if ((obj->anim.placementData != NULL) &&
        (((MMSHScalesPlacement*)obj->anim.placementData)->animDataIndex != MMSH_SCALES_ANIM_DATA_NONE)) {
        objectIndex = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)framesThisStepUnclamped);
        if (objectIndex != 0 && obj->seqIndex == MMSH_SCALES_SEQUENCE_PENDING) {
            slot = ((MMSHScalesState*)obj->extra)->sequence.slot;
            sequenceOwner = NULL;
            objects = ObjList_GetObjects(&objectIndex, &objectCount);
            siblingCount = 0;
            for (objectIndex = 0, groupSlot = (int)(s8)slot; objectIndex < objectCount; objectIndex++) {
                otherObj = *objects;
                if (otherObj->seqIndex == slot) {
                    sequenceOwner = otherObj;
                }
                if ((otherObj->seqIndex == MMSH_SCALES_SEQUENCE_PENDING &&
                     otherObj->anim.classId == MMSH_SCALES_CLASS_ID) &&
                    groupSlot == ((MMSHScalesState*)otherObj->extra)->sequence.slot) {
                    siblingCount++;
                }
                objects++;
            }
            if ((siblingCount <= 1 && sequenceOwner != NULL) && sequenceOwner->seqIndex != MMSH_SCALES_SEQUENCE_NONE) {
                sequenceOwner->seqIndex = MMSH_SCALES_SEQUENCE_NONE;
                (*gObjectTriggerInterface)->endSequence(groupSlot);
            }
            obj->seqIndex = MMSH_SCALES_SEQUENCE_NONE;
            Obj_FreeObject(obj);
        }
    }
}

void mmshScales_init(GameObject* obj, const MMSHScalesPlacement* placement) {
    MMSHScalesState* state = obj->extra;
    MMSHScalesChildSetup* childSetup;
    int cachedAnimDataIndexPlusOne;

    state->sequence.gameBit = placement->sequenceGameBit;
    state->sequence.flags = MMSH_SCALES_SEQUENCE_FLAGS;
    state->sequence.posOffsetDecay = 1.0f / (1.0f + (f32)(u32)placement->positionDamping);
    state->sequence.curveId = MMSH_SCALES_CURVE_NONE;
    cachedAnimDataIndexPlusOne = obj->userData1;
    if (cachedAnimDataIndexPlusOne == 0 && placement->animDataIndex != MMSH_SCALES_DEFAULT_ANIM_DATA_INDEX) {
        (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)placement);
        obj->userData1 = placement->animDataIndex + 1;
    } else if (cachedAnimDataIndexPlusOne != 0 && placement->animDataIndex != cachedAnimDataIndexPlusOne - 1) {
        (*gObjectTriggerInterface)->freeState((u8*)state);
        if (placement->animDataIndex != MMSH_SCALES_ANIM_DATA_NONE) {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)placement);
        }
        obj->userData1 = placement->animDataIndex + 1;
    }
    if (Obj_CanSetupObject() == 0) {
        return;
    }
    childSetup =
        (MMSHScalesChildSetup*)Obj_AllocObjectSetup(sizeof(MMSHScalesChildSetup), CFCRATE_OBJ_SCALESSWORD);
    childSetup->base.posX = obj->anim.localPosX;
    childSetup->base.posY = obj->anim.localPosY;
    childSetup->base.posZ = obj->anim.localPosZ;
    childSetup->base.color[0] = MMSH_SCALES_CHILD_COLOR_RED;
    childSetup->base.color[1] = MMSH_SCALES_CHILD_COLOR_GREEN;
    childSetup->base.color[3] = MMSH_SCALES_CHILD_COLOR_ALPHA;
    obj->childObjs[0] = objSetupObject(&childSetup->base, MMSH_SCALES_CHILD_SETUP_FLAGS, MMSH_SCALES_NO_MAP_LAYER,
                                        MMSH_SCALES_NO_OBJECT_INDEX, NULL);
    ((GameObject*)obj->childObjs[0])->anim.rootMotionScale *= MMSH_SCALES_CHILD_SCALE;
}

void mmshScales_release(void) {
}

void mmshScales_initialise(void) {
}

ObjectDescriptor gMMSHScalesObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmshScales_initialise,
    (ObjectDescriptorCallback)mmshScales_release,
    0,
    (ObjectDescriptorCallback)mmshScales_init,
    (ObjectDescriptorCallback)mmshScales_update,
    (ObjectDescriptorCallback)mmshScales_hitDetect,
    (ObjectDescriptorCallback)mmshScales_render,
    (ObjectDescriptorCallback)mmshScales_free,
    (ObjectDescriptorCallback)mmshScales_getObjectTypeId,
    mmshScales_getExtraSize,
};
