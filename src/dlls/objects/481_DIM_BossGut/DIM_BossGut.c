/*
 * DIM_BossGut (DLL 0x1E1) - DarkIce Mines boss gut cavity object.
 * The object advances and renders the cavity's idle animation, while its
 * sequence callback disables sequence events and clears the hit-volume pair.
 */
#include "dlls/objects/481_DIM_BossGut.h"

#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "sys/objects.h"

#define DIM_BOSS_GUT_OBJECT_SLOT    0x5A
#define DIM_BOSS_GUT_ANIMATION_STEP 0.005f

int DIM_BossGut_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    animUpdate->flags = -1;
    animUpdate->movementState = 0;
    return 0;
}

int DIM_BossGut_getExtraSize(void) {
    return 0;
}

int DIM_BossGut_getObjectTypeId(void) {
    return 0;
}

void DIM_BossGut_free(void) {
}

void DIM_BossGut_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                        s8 shouldRender) {
    int visible;

    visible = shouldRender;
    if (visible != 0) {
        ObjAnim_AdvanceCurrentMove(obj, DIM_BOSS_GUT_ANIMATION_STEP, timeDelta, NULL);
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void DIM_BossGut_hitDetect(void) {
}

void DIM_BossGut_update(void) {
}

void DIM_BossGut_init(GameObject* obj) {
    GameObject* objArg;

    objSetSlot(obj, DIM_BOSS_GUT_OBJECT_SLOT);
    obj->animEventCallback = DIM_BossGut_SeqFn;
    objArg = obj;
    ObjAnim_SetCurrentMove(objArg, 0, 0.0f, 0);
    ObjAnim_AdvanceCurrentMove(objArg, DIM_BOSS_GUT_ANIMATION_STEP, timeDelta, NULL);
}

void DIM_BossGut_release(void) {
}

void DIM_BossGut_initialise(void) {
}

ObjectDescriptor gDIM_BossGutObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    DIM_BossGut_initialise,
    DIM_BossGut_release,
    0,
    (ObjectDescriptorCallback)DIM_BossGut_init,
    DIM_BossGut_update,
    DIM_BossGut_hitDetect,
    (ObjectDescriptorCallback)DIM_BossGut_render,
    DIM_BossGut_free,
    (ObjectDescriptorCallback)DIM_BossGut_getObjectTypeId,
    DIM_BossGut_getExtraSize,
};
