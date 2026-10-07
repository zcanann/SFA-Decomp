/*
 * DIM2RoofRub (DLL 0x00C7) - Dark Ice Mines roof-rub object.
 *
 * Each instance runs a placement-selected animation sequence and responds to
 * sequence events by toggling its ambient effects or spawning dust. Two
 * sequence variants also emit model-scaled particles while rendering.
 */
#include "dlls/objects/199_DIM2RoofRub.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/obj_list.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/objprint_render_api.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "main/objseq.h"

typedef struct DIM2RoofRubHitEffect {
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
    f32 scale;
    u8 effectType;
    u8 mask;
    u8 pad12[2];
} DIM2RoofRubHitEffect;

STATIC_ASSERT(sizeof(DIM2RoofRubHitEffect) == 0x14);
STATIC_ASSERT(offsetof(DIM2RoofRubHitEffect, scale) == 0x0C);
STATIC_ASSERT(offsetof(DIM2RoofRubHitEffect, effectType) == 0x10);
STATIC_ASSERT(offsetof(DIM2RoofRubHitEffect, mask) == 0x11);

#define DIM2ROOFRUB_SEQID_SLIDE 0xa8
#define DIM2ROOFRUB_SEQID_TREAD 0x451

#define DIM2ROOFRUB_SEQEV_TOGGLE_LIGHT 1
#define DIM2ROOFRUB_SEQEV_TOGGLE_HEAVY 2
#define DIM2ROOFRUB_SEQEV_TOGGLE_HITS  3
#define DIM2ROOFRUB_SEQEV_SPAWN_DUST   4

#define DIM2ROOFRUB_EFFECT_LIGHT 0x1
#define DIM2ROOFRUB_EFFECT_HEAVY 0x2
#define DIM2ROOFRUB_EFFECT_HITS  0x4

#define DIM2ROOFRUB_STATEFLAG_CAMERA_RELATIVE 0x4

#define DIM2ROOFRUB_SEQUENCE_CLASS_ID 0x10

#define DIM2ROOFRUB_PARTFX_DUST 0x7fe

#define DIM2ROOFRUB_HIT_EFFECT_COUNT 10

/* Model-space masked-hit effect offsets used while DIM2ROOFRUB_EFFECT_HITS is set. */
static DIM2RoofRubHitEffect sHitEffects[DIM2ROOFRUB_HIT_EFFECT_COUNT] = {
    /* 0 */ {0.0f, 1.669f, -2.582f, 0.01f, 0x6, 0x10, {0, 0}},
    /* 1 */ {2.738f, 0.793f, -1.954f, 0.01f, 0x9, 0x20, {0, 0}},
    /* 2 */ {2.73f, 0.779f, -0.952f, 0.01f, 0x7, 0x20, {0, 0}},
    /* 3 */ {2.795f, -0.974f, -1.945f, 0.01f, 0x9, 0x20, {0, 0}},
    /* 4 */ {2.812f, -1.008f, -0.955f, 0.01f, 0x7, 0x20, {0, 0}},
    /* 5 */ {-2.738f, 0.793f, -1.97f, 0.01f, 0x9, 0x20, {0, 0}},
    /* 6 */ {-2.73f, 0.779f, -0.952f, 0.01f, 0x7, 0x20, {0, 0}},
    /* 7 */ {-2.795f, -0.974f, -1.971f, 0.01f, 0x9, 0x20, {0, 0}},
    /* 8 */ {-2.812f, -1.008f, -0.955f, 0.01f, 0x7, 0x20, {0, 0}},
    /* 9 */ {0.0f, 0.405f, 2.952f, 0.01f, 0x8, 0x40, {0, 0}},
};

void dim2roofrub_spawnEffects(GameObject* obj) {
    PartFxSpawnParams effectParams;
    int effectFlags;

    if ((obj->userData2 & DIM2ROOFRUB_EFFECT_HITS) != 0) {
        u8 effectIndex = 0;
        f32 positionScale = 0.64f;
        DIM2RoofRubHitEffect* effects = sHitEffects;

        for (; effectIndex < DIM2ROOFRUB_HIT_EFFECT_COUNT; effectIndex++) {
            f32 modelScale = obj->anim.rootMotionScale;
            DIM2RoofRubHitEffect* effect = &effects[effectIndex];

            effectParams.posX = positionScale * (modelScale * effect->offsetX);
            effectParams.posY = positionScale * (modelScale * effect->offsetY);
            effectParams.posZ = positionScale * (modelScale * effect->offsetZ);
            objfx_spawnMaskedHitEffect(obj, modelScale * effect->scale, 3, effect->effectType, effect->mask,
                                       &effectParams);
        }
    }
    effectParams.scale = -1.0f;
    effectFlags = obj->userData2;
    if ((effectFlags & DIM2ROOFRUB_EFFECT_LIGHT) != 0) {
        int pulseCount;

        if ((effectFlags & DIM2ROOFRUB_EFFECT_HEAVY) != 0) {
            pulseCount = 6;
        } else {
            pulseCount = 3;
        }
        effectParams.posX = 0.64f * (-0.823f * obj->anim.rootMotionScale);
        effectParams.posY = 0.64f * (-0.084f * obj->anim.rootMotionScale);
        effectParams.posZ = 0.64f * (-2.6f * obj->anim.rootMotionScale);
        objfx_spawnLightPulse(obj, 0.025f * obj->anim.rootMotionScale, 1, 0, pulseCount, 0.7f, &effectParams);
        effectParams.posX = 0.0f;
        effectParams.posY = 0.64f * (0.209f * obj->anim.rootMotionScale);
        effectParams.posZ = 0.64f * (-3.6f * obj->anim.rootMotionScale);
        objfx_spawnLightPulse(obj, 0.025f * obj->anim.rootMotionScale, 1, 0, pulseCount, 0.5f, &effectParams);
        effectParams.posX = 0.64f * (0.823f * obj->anim.rootMotionScale);
        effectParams.posY = 0.64f * (-0.084f * obj->anim.rootMotionScale);
        effectParams.posZ = 0.64f * (-2.6f * obj->anim.rootMotionScale);
        objfx_spawnLightPulse(obj, 0.025f * obj->anim.rootMotionScale, 1, 0, pulseCount, 0.7f, &effectParams);
    }
    if (obj->anim.romDefNo == DIM2ROOFRUB_SEQID_SLIDE) {
        objfx_spawnDirectionalBurst(obj, 7, 1.0f, 5, 1, 10, 6.0f, NULL, 0x20000000);
    } else if (obj->anim.romDefNo == DIM2ROOFRUB_SEQID_TREAD) {
        ObjModel* model = Obj_GetActiveModel(obj);

        model->textureRefs->swapSelector = 2;
        if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, 2, 1, 20, 2.5f, NULL, 0);
        }
    }
}

int dim2roofrub_getExtraSize(void) {
    return sizeof(DIM2RoofRubState);
}

void dim2roofrub_free(GameObject* obj) {
    (*gObjectTriggerInterface)->freeState(obj->extra);
    gTitleMenuControlInterfaceCopy->vtable->func05(obj, 0xffff, 0, 0, 0);
    Sfx_StopObjectChannel(obj, 0x7f);
}

void dim2roofrub_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5) {
    DIM2RoofRubState* state;
    Mtx worldMatrix;
    Mtx playerTranslation;
    Mtx translatedWorld;
    Mtx inverseCameraTranslation;
    Mtx flipY;
    Mtx flipZ;
    Mtx cameraTranslation;
    Mtx cameraMatrix;
    Mtx cameraWithoutTranslation;
    Mtx cameraFlippedY;
    Mtx cameraFlippedYZ;
    Mtx mirroredCamera;
    Mtx renderMatrix;

    dim2roofrub_spawnEffects(obj);
    state = obj->extra;
    if ((state->sequence.stateFlags & DIM2ROOFRUB_STATEFLAG_CAMERA_RELATIVE) != 0) {
        DIM2RoofRubPlacement* placement;
        GameObject* camera;

        Obj_BuildWorldTransformMatrix(obj, (f32*)worldMatrix, 0);
        placement = (DIM2RoofRubPlacement*)obj->anim.placementData;
        PSMTXTrans(playerTranslation, -(placement->base.posX - playerMapOffsetX), -placement->base.posY,
                   -(placement->base.posZ - playerMapOffsetZ));
        PSMTXConcat(playerTranslation, worldMatrix, translatedWorld);
        camera = (GameObject*)(*gCameraInterface)->getCamera();
        camera->anim.rotY += 0x8000;
        camera->anim.rootMotionScale = 1.0f;
        Obj_BuildWorldTransformMatrix(camera, (f32*)cameraMatrix, 0);
        camera->anim.rotY += 0x8000;
        camera->anim.rootMotionScale = 0.0f;
        PSMTXTrans(inverseCameraTranslation, -cameraMatrix[0][3], -cameraMatrix[1][3], -cameraMatrix[2][3]);
        PSMTXRotRad(flipY, 'y', 3.1415927f);
        PSMTXRotRad(flipZ, 'z', 3.1415927f);
        PSMTXTrans(cameraTranslation, cameraMatrix[0][3], cameraMatrix[1][3], cameraMatrix[2][3]);
        PSMTXConcat(inverseCameraTranslation, cameraMatrix, cameraWithoutTranslation);
        PSMTXConcat(flipY, cameraWithoutTranslation, cameraFlippedY);
        PSMTXConcat(flipZ, cameraFlippedY, cameraFlippedYZ);
        PSMTXConcat(cameraTranslation, cameraFlippedYZ, mirroredCamera);
        PSMTXConcat(mirroredCamera, translatedWorld, renderMatrix);
        objSetCurrentMatrix(renderMatrix);
        objRenderModel(obj);
    } else {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void dim2roofrub_update(GameObject* obj) {
    ObjSeqState* sequence = &((DIM2RoofRubState*)obj->extra)->sequence;
    DIM2RoofRubPlacement* placement = (DIM2RoofRubPlacement*)obj->anim.placementData;

    if (placement != NULL && placement->animDataIndex != -1) {
        PartFxSpawnParams dustParams;
        int objectCount;
        int result;

        for (result = 0; result < sequence->eventCount; result++) {
            int eventId = sequence->eventIds[result];

            switch (eventId) {
            case DIM2ROOFRUB_SEQEV_TOGGLE_LIGHT:
                obj->userData2 ^= DIM2ROOFRUB_EFFECT_LIGHT;
                break;
            case DIM2ROOFRUB_SEQEV_TOGGLE_HEAVY:
                obj->userData2 ^= DIM2ROOFRUB_EFFECT_HEAVY;
                break;
            case DIM2ROOFRUB_SEQEV_TOGGLE_HITS:
                obj->userData2 ^= DIM2ROOFRUB_EFFECT_HITS;
                break;
            case DIM2ROOFRUB_SEQEV_SPAWN_DUST: {
                int dustCount;

                dustParams.posX = obj->anim.localPosX;
                dustParams.posY = obj->anim.localPosY;
                dustParams.posZ = obj->anim.localPosZ;
                for (dustCount = 3; dustCount != 0; dustCount--) {
                    (*gPartfxInterface)->spawnEffect(obj, DIM2ROOFRUB_PARTFX_DUST, &dustParams, 0x200001, -1, NULL);
                }
                break;
            }
            }
        }
        result = (*gObjectTriggerInterface)->update((u8*)obj, timeDelta);
        if (result != 0 && obj->seqIndex == -2) {
            int sequenceIndex = sequence->slot;
            GameObject** objects;
            int slot;
            int siblingCount;
            GameObject* sequenceOwner = NULL;

            objects = ObjList_GetObjects(&result, &objectCount);
            result = siblingCount = 0;
            slot = sequenceIndex;
            for (; result < objectCount; result++) {
                GameObject* other = *objects;

                if (other->seqIndex == sequenceIndex) {
                    sequenceOwner = *objects;
                }
                if (other->seqIndex == -2 && other->anim.classId == DIM2ROOFRUB_SEQUENCE_CLASS_ID) {
                    ObjSeqState* otherSequence = &((DIM2RoofRubState*)other->extra)->sequence;

                    if (slot == otherSequence->slot) {
                        siblingCount++;
                    }
                }
                objects++;
            }
            if (siblingCount <= 1 && sequenceOwner != NULL && sequenceOwner->seqIndex != -1) {
                sequenceOwner->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(slot);
            }
            obj->seqIndex = -1;
        }
    }
}

void dim2roofrub_init(GameObject* obj, DIM2RoofRubPlacement* placement) {
    ObjSeqState* sequence;
    int loadedAnimDataIndexPlusOne;

    objSetSlot(obj, 0x64);
    sequence = obj->extra;
    sequence->gameBit = placement->sequenceGameBit;
    sequence->flags = -1;
    {
        f32 one = 1.0f;

        sequence->posOffsetDecay = one / (one + (f32)(u32)placement->positionDamping);
    }
    sequence->curveId = -1;
    sequence->animEntries = NULL;
    sequence->cmds = NULL;
    sequence->baseRotX = 0;
    sequence->baseRotY = 0;
    obj->userData2 = 0;
    loadedAnimDataIndexPlusOne = obj->userData1;
    if (loadedAnimDataIndexPlusOne == 0 && placement->animDataIndex != 1) {
        (*gObjectTriggerInterface)->loadAnimData((u8*)sequence, (u8*)placement);
        obj->userData1 = placement->animDataIndex + 1;
    } else if (loadedAnimDataIndexPlusOne != 0 && placement->animDataIndex != loadedAnimDataIndexPlusOne - 1) {
        (*gObjectTriggerInterface)->freeState((u8*)sequence);
        if (placement->animDataIndex != -1) {
            (*gObjectTriggerInterface)->loadAnimData((u8*)sequence, (u8*)placement);
        }
        obj->userData1 = placement->animDataIndex + 1;
    }
    {
        ObjModelState* modelState = obj->anim.modelState;

        if (modelState != NULL) {
            modelState->shadowTintA = 0x64;
            obj->anim.modelState->shadowTintB = 0x96;
        }
    }
}

ObjectDescriptor gDIM2RoofRubObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim2roofrub_init,
    (ObjectDescriptorCallback)dim2roofrub_update,
    0,
    (ObjectDescriptorCallback)dim2roofrub_render,
    (ObjectDescriptorCallback)dim2roofrub_free,
    0,
    dim2roofrub_getExtraSize,
};
