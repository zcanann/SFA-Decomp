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

typedef struct EcshCupState
{
    f32 startPosX;
    f32 startPosY;
    f32 startPosZ;
    f32 velX;
    f32 velY;
    f32 velZ;
    f32 spawnPosY;
    f32 spawnTimer;
    f32 bobTimer;
    s32 currentMode;
    s32 slotId;
    s16 spinRate;
    s8 bobDir;
    u8 pad2F[0x30 - 0x2F];
} EcshCupState;

typedef struct EcshCupPlacement
{
    u8 pad00[0x1a];
    s16 slotId; /* 0x1a */
} EcshCupPlacement;

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

u32 gEcShCupNearestObject;
const CupVec3 lbl_802C23B8 = {0.0f, 0.0f, 0.0f};

int ecsh_cup_getExtraSize(void)
{
    return 0x30;
}

int ecsh_cup_getObjectTypeId(void)
{
    return 0x0;
}

void ecsh_cup_free(int* obj)
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

void ecsh_cup_update(short* obj)
{
    f32 dist;
    int mode;
    int m;
    u8 buf[4];
    CupVec3 v;
    GameObject* player = Obj_GetPlayerObject();
    EcshCupState* state = ((GameObject*)obj)->extra;
    f32 fade;

    v = lbl_802C23B8;
    dist = 500.0f;
    mode = -1;
    buf[0] = 0;
    if (gEcShCupNearestObject == 0)
    {
        gEcShCupNearestObject = ObjGroup_FindNearestObject(ECSHCUP_TARGET_OBJGROUP, (int)obj, &dist);
    }
    if (gEcShCupNearestObject != 0 && ((GameObject*)gEcShCupNearestObject)->anim.classId != 0)
    {
        (*(void (*)(int*, u8*)) * (int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x28))(&mode, buf);
        *obj += state->spinRate;
        if (mode != 6)
        {
            state->spawnTimer -= timeDelta;
            if (state->spawnTimer <= 0.0f)
            {
                state->spawnTimer = 10.0f;
                if (mode != 3 && mode != 6 && mode != 7)
                {
                    (*gPartfxInterface)->spawnObject(obj, ECSHCUP_PARTFX_IDLE, NULL, 0, -1, NULL);
                }
            }
        }
        state->bobTimer -= timeDelta;
        if (state->bobTimer <= 0.0f)
        {
            state->bobDir = (u32)state->bobDir * -1;
            state->bobTimer = 100.0f;
        }
        ((GameObject*)obj)->anim.localPosY = 0.02f * state->bobDir + ((GameObject*)obj)->anim.localPosY;
        if (mode == 1 && state->currentMode == 1)
        {
            ((GameObject*)obj)->anim.localPosX = state->velX * timeDelta + ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)obj)->anim.localPosZ = state->velZ * timeDelta + ((GameObject*)obj)->anim.localPosZ;
            ObjHits_EnableObject((GameObject*)obj);
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, ECSHCUP_HIT_VOLUME_SLOT, 1, 0);
            ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
        }
        else
        {
            ObjHits_EnableObject((GameObject*)obj);
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, 0, 0, 0);
            ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
        }
        m = mode;
        if (m == 6)
        {
            if (((GameObject*)obj)->anim.localPosY < state->spawnPosY)
            {
                ((GameObject*)obj)->anim.localPosY = 0.5f * timeDelta + ((GameObject*)obj)->anim.localPosY;
            }
            if (((GameObject*)obj)->anim.renderAlpha != 0xff)
            {
                fade = (f32)(u32)((GameObject*)obj)->anim.renderAlpha;
                fade += 2.0f * timeDelta;
                if (fade >= 255.0f)
                {
                    fade = 255.0f;
                }
                ((GameObject*)obj)->anim.renderAlpha = (u8)fade;
            }
            state->spawnTimer -= timeDelta;
            if (state->spawnTimer <= 0.0f)
            {
                state->spawnTimer = 10.0f;
                (*gPartfxInterface)->spawnObject(obj, ECSHCUP_PARTFX_TRANSITION, NULL, 0, -1, NULL);
            }
        }
        else if (m == 7)
        {
            if (((GameObject*)obj)->anim.localPosY > state->spawnPosY - 50.0f)
            {
                ((GameObject*)obj)->anim.localPosY = -(0.5f * timeDelta - ((GameObject*)obj)->anim.localPosY);
                state->spawnTimer -= timeDelta;
                if (state->spawnTimer <= 0.0f)
                {
                    state->spawnTimer = 10.0f;
                    if (mode != 3)
                    {
                        (*gPartfxInterface)->spawnObject(obj, ECSHCUP_PARTFX_TRANSITION, NULL, 0, -1, NULL);
                    }
                }
            }
            if (((GameObject*)obj)->anim.renderAlpha != 0)
            {
                fade = (f32)(u32)((GameObject*)obj)->anim.renderAlpha;
                fade = fade - 2.0f * timeDelta;
                if (fade <= 0.0f)
                {
                    fade = 0.0f;
                }
                ((GameObject*)obj)->anim.renderAlpha = (u8)fade;
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
            (*(void (*)(int, f32*, f32*)) *
             (int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x24))((u8)state->slotId, &v.x, &v.z);
            state->velX = (v.x - ((GameObject*)obj)->anim.localPosX) / 100.0f;
            state->velZ = (v.z - ((GameObject*)obj)->anim.localPosZ) / 100.0f;
            state->startPosX = ((GameObject*)obj)->anim.localPosX;
            state->startPosZ = ((GameObject*)obj)->anim.localPosZ;
            state->currentMode = mode;
        }
        else if (m == 0 && m != state->currentMode)
        {
            state->velX = 0.0f;
            state->velZ = 0.0f;
            state->currentMode = mode;
        }
        else if (m == 2 && m != state->currentMode)
        {
            state->velX = 0.0f;
            state->velZ = 0.0f;
            (*(void (*)(int, f32, f32)) * (int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x2c))(
                (u8)state->slotId, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ);
            state->currentMode = mode;
        }
        else if (m == 3 && m != state->currentMode)
        {
            state->currentMode = mode;
        }
        else if (m == 4 && m != state->currentMode)
        {
            (*(void (*)(int, f32*, f32*)) *
             (int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x24))((u8)state->slotId, &v.x, &v.z);
            ((GameObject*)obj)->anim.localPosX = v.x;
            ((GameObject*)obj)->anim.localPosZ = v.z;
            state->currentMode = mode;
        }
        else if (m == 5)
        {
            if (player != NULL)
            {
                if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &player->anim.worldPosX) < 30.0f)
                {
                    (*(void (*)(int)) *
                     (int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x30))((u8)state->slotId);
                    if (state->slotId == buf[0])
                    {
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    }
                }
            }
        }
    }
}

void ecsh_cup_init(int obj, int def)
{
    int state;
    f32 dist;
    EcshCupPlacement* p = (EcshCupPlacement*)def;

    state = *(int*)&((GameObject*)obj)->extra;
    dist = 500.0f;
    gEcShCupNearestObject = 0;
    ((EcshCupState*)state)->startPosX = ((GameObject*)obj)->anim.localPosX;
    ((EcshCupState*)state)->startPosY = ((GameObject*)obj)->anim.localPosY;
    ((EcshCupState*)state)->startPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((EcshCupState*)state)->spawnPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - 50.0f;
    {
        f32 fz = 0.0f;
        ((EcshCupState*)state)->velX = fz;
        ((EcshCupState*)state)->velY = fz;
        ((EcshCupState*)state)->velZ = fz;
    }
    ((EcshCupState*)state)->currentMode = 0;
    ((EcshCupState*)state)->slotId = p->slotId;
    ((EcshCupState*)state)->bobTimer = randomGetRange(0, 0x258);
    ((EcshCupState*)state)->spinRate = randomGetRange(-0x320, 0x320);
    *(u8*)&((EcshCupState*)state)->bobDir = 1;
    ((GameObject*)obj)->anim.renderAlpha = 0;
    ((EcshCupState*)state)->spawnTimer = 0.0f;
    if (gEcShCupNearestObject == 0)
    {
        gEcShCupNearestObject = ObjGroup_FindNearestObject(ECSHCUP_TARGET_OBJGROUP, obj, &dist);
    }
    ObjHits_EnableObject((GameObject*)obj);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, 0, 0, 0);
    ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
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
