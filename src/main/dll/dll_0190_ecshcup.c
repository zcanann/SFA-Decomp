/* DLL 0x190 - ECSHCup [801C835C-801C8B68) */
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/vecmath_distance_api.h"
#include "main/object_render.h"
#include "main/dll/dll_0190_ecshcup.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/objseq.h"
#include "main/obj_group.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "main/object_descriptor.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

typedef struct
{
    f32 x;
    f32 y;
    f32 z;
} CupVec3;

#define ECSHCUP_TARGET_OBJGROUP 0xb

/* periodic particle emitted while the cup is in its normal tracking mode */
#define ECSHCUP_PARTFX_IDLE 0x270
/* periodic particle emitted during the rise (mode 6) / sink (mode 7) sequences */
#define ECSHCUP_PARTFX_TRANSITION 0x271
#define ECSHCUP_HIT_VOLUME_SLOT   10

GameObject* gEcShCupNearestObject;
const CupVec3 lbl_802C23B8 = {0.0f, 0.0f, 0.0f};

int ecsh_cup_getExtraSize(void)
{
    return sizeof(EcshCupState);
}

int ecsh_cup_getObjectTypeId(void)
{
    return 0x0;
}

void ecsh_cup_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void ecsh_cup_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void ecsh_cup_hitDetect(void)
{
}

void ecsh_cup_update(GameObject* obj)
{
    f32 dist;
    int mode;
    int m;
    u8 buf[4];
    CupVec3 v;
    GameObject* player = Obj_GetPlayerObject();
    EcshCupState* state = obj->extra;
    f32 fade;

    v = lbl_802C23B8;
    dist = 500.0f;
    mode = -1;
    buf[0] = 0;
    if (gEcShCupNearestObject == NULL)
    {
        gEcShCupNearestObject =
            (GameObject*)ObjGroup_FindNearestObject(ECSHCUP_TARGET_OBJGROUP, obj, &dist);
    }
    if (gEcShCupNearestObject != NULL && gEcShCupNearestObject->anim.classId != 0)
    {
        (*(EcshCupControllerInterfaceVTable**)gEcShCupNearestObject->anim.dll)->getMode(&mode, buf);
        obj->anim.rotX += state->spinRate;
        if (mode != 6)
        {
            state->particleTimer -= timeDelta;
            if (state->particleTimer <= 0.0f)
            {
                state->particleTimer = 10.0f;
                if (mode != 3 && mode != 6 && mode != 7)
                {
                    (*gPartfxInterface)->spawnObject(obj, ECSHCUP_PARTFX_IDLE, NULL, 0, -1, NULL);
                }
            }
        }
        state->bobTimer -= timeDelta;
        if (state->bobTimer <= 0.0f)
        {
            state->bobDirection = (u32)state->bobDirection * -1;
            state->bobTimer = 100.0f;
        }
        obj->anim.localPosY = 0.02f * state->bobDirection + obj->anim.localPosY;
        if (mode == 1 && state->currentMode == 1)
        {
            obj->anim.localPosX = state->velocityX * timeDelta + obj->anim.localPosX;
            obj->anim.localPosZ = state->velocityZ * timeDelta + obj->anim.localPosZ;
            ObjHits_EnableObject(obj);
            ObjHits_SetHitVolumeSlot(&obj->anim, ECSHCUP_HIT_VOLUME_SLOT, 1, 0);
            ObjHits_SyncObjectPositionIfDirty(obj);
        }
        else
        {
            ObjHits_EnableObject(obj);
            ObjHits_SetHitVolumeSlot(&obj->anim, 0, 0, 0);
            ObjHits_SyncObjectPositionIfDirty(obj);
        }
        m = mode;
        if (m == 6)
        {
            if (obj->anim.localPosY < state->transitionHeight)
            {
                obj->anim.localPosY = 0.5f * timeDelta + obj->anim.localPosY;
            }
            if (obj->anim.renderAlpha != 0xff)
            {
                fade = (f32)(u32)obj->anim.renderAlpha;
                fade += 2.0f * timeDelta;
                if (fade >= 255.0f)
                {
                    fade = 255.0f;
                }
                obj->anim.renderAlpha = (u8)fade;
            }
            state->particleTimer -= timeDelta;
            if (state->particleTimer <= 0.0f)
            {
                state->particleTimer = 10.0f;
                (*gPartfxInterface)->spawnObject(obj, ECSHCUP_PARTFX_TRANSITION, NULL, 0, -1, NULL);
            }
        }
        else if (m == 7)
        {
            if (obj->anim.localPosY > state->transitionHeight - 50.0f)
            {
                obj->anim.localPosY = -(0.5f * timeDelta - obj->anim.localPosY);
                state->particleTimer -= timeDelta;
                if (state->particleTimer <= 0.0f)
                {
                    state->particleTimer = 10.0f;
                    if (mode != 3)
                    {
                        (*gPartfxInterface)->spawnObject(obj, ECSHCUP_PARTFX_TRANSITION, NULL, 0, -1, NULL);
                    }
                }
            }
            if (obj->anim.renderAlpha != 0)
            {
                fade = (f32)(u32)obj->anim.renderAlpha;
                fade = fade - 2.0f * timeDelta;
                if (fade <= 0.0f)
                {
                    fade = 0.0f;
                }
                obj->anim.renderAlpha = (u8)fade;
            }
        }
        else if (m == 8 && m != state->currentMode)
        {
            if (state->slotId == buf[0])
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            }
            state->currentMode = mode;
        }
        else if (m == 1 && m != state->currentMode)
        {
            (*(EcshCupControllerInterfaceVTable**)gEcShCupNearestObject->anim.dll)
                ->getSlotPosition((u8)state->slotId, &v.x, &v.z);
            state->velocityX = (v.x - obj->anim.localPosX) / 100.0f;
            state->velocityZ = (v.z - obj->anim.localPosZ) / 100.0f;
            state->startPosX = obj->anim.localPosX;
            state->startPosZ = obj->anim.localPosZ;
            state->currentMode = mode;
        }
        else if (m == 0 && m != state->currentMode)
        {
            state->velocityX = 0.0f;
            state->velocityZ = 0.0f;
            state->currentMode = mode;
        }
        else if (m == 2 && m != state->currentMode)
        {
            state->velocityX = 0.0f;
            state->velocityZ = 0.0f;
            (*(EcshCupControllerInterfaceVTable**)gEcShCupNearestObject->anim.dll)
                ->setSlotPosition((u8)state->slotId, obj->anim.localPosX, obj->anim.localPosZ);
            state->currentMode = mode;
        }
        else if (m == 3 && m != state->currentMode)
        {
            state->currentMode = mode;
        }
        else if (m == 4 && m != state->currentMode)
        {
            (*(EcshCupControllerInterfaceVTable**)gEcShCupNearestObject->anim.dll)
                ->getSlotPosition((u8)state->slotId, &v.x, &v.z);
            obj->anim.localPosX = v.x;
            obj->anim.localPosZ = v.z;
            state->currentMode = mode;
        }
        else if (m == 5)
        {
            if (player != NULL)
            {
                if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < 30.0f)
                {
                    (*(EcshCupControllerInterfaceVTable**)gEcShCupNearestObject->anim.dll)
                        ->activateSlot((u8)state->slotId);
                    if (state->slotId == buf[0])
                    {
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    }
                }
            }
        }
    }
}

void ecsh_cup_init(GameObject* obj, EcshCupPlacement* placement)
{
    EcshCupState* state;
    f32 dist;

    state = obj->extra;
    dist = 500.0f;
    gEcShCupNearestObject = NULL;
    state->startPosX = obj->anim.localPosX;
    state->startPosY = obj->anim.localPosY;
    state->startPosZ = obj->anim.localPosZ;
    state->transitionHeight = obj->anim.localPosY;
    obj->anim.localPosY = obj->anim.localPosY - 50.0f;
    {
        f32 fz = 0.0f;
        state->velocityX = fz;
        state->velocityY = fz;
        state->velocityZ = fz;
    }
    state->currentMode = 0;
    state->slotId = placement->slotId;
    state->bobTimer = randomGetRange(0, 0x258);
    state->spinRate = randomGetRange(-0x320, 0x320);
    state->bobDirection = 1;
    obj->anim.renderAlpha = 0;
    state->particleTimer = 0.0f;
    if (gEcShCupNearestObject == NULL)
    {
        gEcShCupNearestObject =
            (GameObject*)ObjGroup_FindNearestObject(ECSHCUP_TARGET_OBJGROUP, obj, &dist);
    }
    ObjHits_EnableObject(obj);
    ObjHits_SetHitVolumeSlot(&obj->anim, 0, 0, 0);
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void ecsh_cup_release(void)
{
}

void ecsh_cup_initialise(void)
{
}

ObjectDescriptor gECSH_CupObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ecsh_cup_initialise, (ObjectDescriptorCallback)ecsh_cup_release, 0,
    (ObjectDescriptorCallback)ecsh_cup_init, (ObjectDescriptorCallback)ecsh_cup_update,
    (ObjectDescriptorCallback)ecsh_cup_hitDetect, (ObjectDescriptorCallback)ecsh_cup_render,
    (ObjectDescriptorCallback)ecsh_cup_free, (ObjectDescriptorCallback)ecsh_cup_getObjectTypeId,
    ecsh_cup_getExtraSize,
};
