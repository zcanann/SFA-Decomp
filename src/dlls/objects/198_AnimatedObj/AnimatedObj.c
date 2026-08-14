/*
 * AnimatedObj (DLL 0x00C6) - generic animation-sequence object.
 *
 * Each instance loads sequence data selected by its placement, advances that
 * sequence every frame, and renders camera-relative sequences with a corrected
 * world transform. The AnimKrystal variant also attaches and detaches a staff
 * child in response to sequence events.
 */
#include "dlls/objects/198_AnimatedObj.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/frame_timing.h"
#include "main/maketex_sequence_api.h"
#include "main/obj_link.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "main/objprint_render_api.h"
#include "main/objseq.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define ANIMATEDOBJ_CLASS_ID                  0x10
#define ANIMATEDOBJ_CHILD_OBJ_STAFF           0x69
#define ANIMATEDOBJ_SEQID_ANIM_KRYSTAL        0x774
#define ANIMATEDOBJ_SEQEV_ATTACH_STAFF        0xa
#define ANIMATEDOBJ_SEQEV_DETACH_STAFF        0xb
#define ANIMATEDOBJ_STATEFLAG_CAMERA_RELATIVE 0x4

int animatedobj_getExtraSize(void) {
    return sizeof(AnimatedObjState);
}

void animatedobj_free(GameObject* obj, int clearSequence) {
    (*gObjectTriggerInterface)->freeState(obj->extra);
    gTitleMenuControlInterfaceCopy->vtable->func05(obj, 0xffff, 0, 0, 0);
    Sfx_RemoveLoopedObjectSoundForObject(obj);
    Sfx_StopObjectChannel(obj, 0x7f);
    if (obj->anim.romDefNo == ANIMATEDOBJ_SEQID_ANIM_KRYSTAL && obj->childCount != 0) {
        Obj_FreeObject(obj->childObjs[0]);
        ObjLink_DetachChild(obj, obj->childObjs[0]);
    }
    if (clearSequence != 0) {
        clearCurSeqNo();
    }
}

void animatedobj_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 unusedVisible) {
    AnimatedObjState* state;
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

    (void)unusedVisible;
    state = obj->extra;
    if ((state->sequence.stateFlags & ANIMATEDOBJ_STATEFLAG_CAMERA_RELATIVE) != 0) {
        AnimatedObjPlacement* placement;
        GameObject* camera;

        Obj_BuildWorldTransformMatrix(obj, (f32*)worldMatrix, 0);
        placement = (AnimatedObjPlacement*)obj->anim.placementData;
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

void animatedobj_update(GameObject* obj) {
    AnimatedObjPlacement* placement;
    int result;
    int objectCount;
    int sequenceIndex;
    GameObject* sequenceOwner;
    ObjSeqState* sequence;
    GameObject** objects;
    int slot;
    int siblingCount;
    GameObject* other;
    int eventIndex;
    GameObject* child;

    sequence = &((AnimatedObjState*)obj->extra)->sequence;
    placement = (AnimatedObjPlacement*)obj->anim.placementData;
    if (placement != NULL && placement->animDataIndex != -1) {
        result = (*gObjectTriggerInterface)->update((u8*)obj, timeDelta);
        if (result != 0 && obj->seqIndex == -2) {
            sequenceIndex = sequence->slot;
            sequenceOwner = NULL;
            objects = ObjList_GetObjects(&result, &objectCount);
            siblingCount = 0;
            result = 0;
            slot = (s8)sequenceIndex;
            while (result < objectCount) {
                other = *objects;
                if (other->seqIndex == sequenceIndex) {
                    sequenceOwner = *objects;
                }
                if (other->seqIndex == -2 && other->anim.classId == ANIMATEDOBJ_CLASS_ID) {
                    sequence = &((AnimatedObjState*)other->extra)->sequence;
                    if (slot == sequence->slot) {
                        siblingCount++;
                    }
                }
                objects++;
                result++;
            }
            if (siblingCount <= 1 && sequenceOwner != NULL && sequenceOwner->seqIndex != -1) {
                sequenceOwner->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(slot);
            }
            obj->seqIndex = -1;
            obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        switch (obj->anim.romDefNo) {
        case ANIMATEDOBJ_SEQID_ANIM_KRYSTAL: {
            for (eventIndex = 0; eventIndex < sequence->eventCount; eventIndex++) {
                switch (sequence->eventIds[eventIndex]) {
                case ANIMATEDOBJ_SEQEV_ATTACH_STAFF:
                    if (Obj_IsLoadingLocked() != 0) {
                        child = objSetupObject(Obj_AllocObjectSetup(sizeof(ObjPlacement), ANIMATEDOBJ_CHILD_OBJ_STAFF),
                                                4, -1, -1, NULL);
                        ObjLink_AttachChild(obj, child, 0);
                        ObjAnim_SetCurrentMove(child, 0, 0.0f, 0);
                        ObjAnim_AdvanceCurrentMove(child, 1.0f, timeDelta, NULL);
                    }
                    break;
                case ANIMATEDOBJ_SEQEV_DETACH_STAFF:
                    if (obj->childCount != 0) {
                        Obj_FreeObject(obj->childObjs[0]);
                        ObjLink_DetachChild(obj, obj->childObjs[0]);
                    }
                    break;
                }
            }
            break;
        }
        }
    }
}

void animatedobj_init(GameObject* obj, AnimatedObjPlacement* placement) {
    AnimatedObjState* state;
    ObjSeqState* sequence;
    int loadedAnimDataIndexPlusOne;

    objSetSlot(obj, 0x64);
    state = obj->extra;
    sequence = &state->sequence;
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
    sequence->freeCallback = NULL;
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
    Obj_SetModelRenderOpAlpha(obj, 0xff);
}

ObjectDescriptor gAnimatedObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)animatedobj_init,
    (ObjectDescriptorCallback)animatedobj_update,
    0,
    (ObjectDescriptorCallback)animatedobj_render,
    (ObjectDescriptorCallback)animatedobj_free,
    0,
    animatedobj_getExtraSize,
};
