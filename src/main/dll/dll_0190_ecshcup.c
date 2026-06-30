/* DLL 0x190 - ECSHCup [801C835C-801C83D0) */
#include "main/dll_000A_expgfx.h"
#include "main/objseq.h"
#include "main/game_object.h"
#include "main/engine_shared.h"

extern void objRenderFn_8003b8f4(f32);
extern const f32 lbl_803E5060;
extern void ObjHits_SetHitVolumeSlot(u32 objPtr, int hitVolume, int hitType, int sourceSlot);
extern u32 ObjHits_SyncObjectPositionIfDirty();
extern u32 ObjHits_EnableObject();
extern u32 ObjGroup_FindNearestObject();
extern const f32 lbl_803E5064;
extern const f32 lbl_803E5068;
extern const f32 lbl_803E506C;
extern const f32 lbl_803E5070;
extern const f32 lbl_803E5074;
extern const f32 lbl_803E5078;
extern const f32 lbl_803E507C;
extern const f32 lbl_803E5080;
extern const f32 lbl_803E5084;
extern const f32 lbl_803E5088;
extern u32 gEcShCupNearestObject;
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_802C23B8[];

extern int getAngle(float y, float x);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern const f32 lbl_803E50A0;
extern const f32 lbl_803E50A4;
extern const f32 lbl_803E50A8;
extern const f32 lbl_803E50AC;
extern const f32 gEcShCupPi;
extern const f32 gEcShCupAngleToRadDivisor;
extern const f32 lbl_803E50B8;
extern const f32 lbl_803E50BC;
extern const f32 lbl_803E50C0;
extern const f32 lbl_803E50C4;
extern const f32 lbl_803E50C8;

void ecsh_cup_hitDetect(void)
{
}

int gpsh_scene_getExtraSize(void);
int ecsh_cup_getExtraSize(void) { return 0x30; }
int ecsh_cup_getObjectTypeId(void) { return 0x0; }

void ecsh_cup_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5060);
}

void ecsh_cup_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void gpsh_scene_init(int* obj, int* def);

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

typedef struct
{
    f32 x;
    f32 y;
    f32 z;
} CupVec3;

#pragma peephole off
void ecsh_cup_update(short* obj)
{
    f32 dist;
    int mode;
    int m;
    u8 buf[4];
    CupVec3 v;
    GameObject* player = Obj_GetPlayerObject();
    EcshCupState* state = ((GameObject*)obj)->extra;
    f32 a;

    v = *(CupVec3*)lbl_802C23B8;
    dist = lbl_803E5064;
    mode = -1;
    buf[0] = 0;
    if (gEcShCupNearestObject == 0)
    {
        gEcShCupNearestObject = ObjGroup_FindNearestObject(0xb, obj, &dist);
    }
    if (gEcShCupNearestObject != 0 && *(short*)(gEcShCupNearestObject + 0x44) != 0)
    {
        (*(void (*)(int*, u8*))*(int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x28))(&mode, buf);
        *obj += state->spinRate;
        if (mode != 6)
        {
            state->spawnTimer -= timeDelta;
            if (state->spawnTimer <= lbl_803E5068)
            {
                state->spawnTimer = lbl_803E506C;
                if (mode != 3 && mode != 6 && mode != 7)
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x270, NULL, 0, -1, NULL);
                }
            }
        }
        state->bobTimer -= timeDelta;
        if (state->bobTimer <= lbl_803E5068)
        {
            state->bobDir = -state->bobDir;
            state->bobTimer = lbl_803E5070;
        }
        ((GameObject*)obj)->anim.localPosY = lbl_803E5074 * state->bobDir + ((GameObject*)obj)->
            anim.localPosY;
        if (mode == 1 && state->currentMode == 1)
        {
            ((GameObject*)obj)->anim.localPosX = state->velX * timeDelta + ((GameObject*)obj)->anim.
                localPosX;
            ((GameObject*)obj)->anim.localPosZ = state->velZ * timeDelta + ((GameObject*)obj)->anim.
                localPosZ;
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 10, 1, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        }
        else
        {
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 0, 0, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        }
        m = mode;
        if (m == 6)
        {
            if (((GameObject*)obj)->anim.localPosY < state->spawnPosY)
            {
                ((GameObject*)obj)->anim.localPosY = lbl_803E5078 * timeDelta + ((GameObject*)obj)->anim.localPosY;
            }
            if (*(u8*)((char*)obj + 0x37) != 0xff)
            {
                a = (f32)(u32) * (u8*)((char*)obj + 0x37);
                a = lbl_803E507C * timeDelta + a;
                if (a >= lbl_803E5080)
                {
                    a = lbl_803E5080;
                }
                *(u8*)((char*)obj + 0x37) = (u8)a;
            }
            state->spawnTimer -= timeDelta;
            if (state->spawnTimer <= lbl_803E5068)
            {
                state->spawnTimer = lbl_803E506C;
                (*gPartfxInterface)->spawnObject(obj, 0x271, NULL, 0, -1, NULL);
            }
        }
        else if (m == 7)
        {
            if (((GameObject*)obj)->anim.localPosY > state->spawnPosY - lbl_803E5084)
            {
                ((GameObject*)obj)->anim.localPosY = -(lbl_803E5078 * timeDelta - ((GameObject*)obj)->anim.localPosY);
                state->spawnTimer -= timeDelta;
                if (state->spawnTimer <= lbl_803E5068)
                {
                    state->spawnTimer = lbl_803E506C;
                    if (mode != 3)
                    {
                        (*gPartfxInterface)->spawnObject(obj, 0x271, NULL, 0, -1, NULL);
                    }
                }
            }
            if (*(u8*)((char*)obj + 0x37) != 0)
            {
                a = (f32)(u32) * (u8*)((char*)obj + 0x37);
                a = a - lbl_803E507C * timeDelta;
                if (a <= lbl_803E5068)
                {
                    a = lbl_803E5068;
                }
                *(u8*)((char*)obj + 0x37) = (u8)a;
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
            (*(void (*)(int, f32*, f32*))*(int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x24))(
                (u8)state->slotId, &v.x, &v.z);
            state->velX = (v.x - ((GameObject*)obj)->anim.localPosX) / lbl_803E5070;
            state->velZ = (v.z - ((GameObject*)obj)->anim.localPosZ) / lbl_803E5070;
            state->startPosX = ((GameObject*)obj)->anim.localPosX;
            state->startPosZ = ((GameObject*)obj)->anim.localPosZ;
            state->currentMode = mode;
        }
        else if (m == 0 && m != state->currentMode)
        {
            state->velX = lbl_803E5068;
            state->velZ = lbl_803E5068;
            state->currentMode = mode;
        }
        else if (m == 2 && m != state->currentMode)
        {
            state->velX = lbl_803E5068;
            state->velZ = lbl_803E5068;
            (*(void (*)(int, f32, f32))*(int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x2c))(
                (u8)state->slotId, ((GameObject*)obj)->anim.localPosX,
                ((GameObject*)obj)->anim.localPosZ);
            state->currentMode = mode;
        }
        else if (m == 3 && m != state->currentMode)
        {
            state->currentMode = mode;
        }
        else if (m == 4 && m != state->currentMode)
        {
            (*(void (*)(int, f32*, f32*))*(int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x24))(
                (u8)state->slotId, &v.x, &v.z);
            ((GameObject*)obj)->anim.localPosX = v.x;
            ((GameObject*)obj)->anim.localPosZ = v.z;
            state->currentMode = mode;
        }
        else if (m == 5)
        {
            if (player != NULL)
            {
                if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &player->anim.worldPosX) < lbl_803E5088)
                {
                    (*(void (*)(int))*(int*)(*(int*)(*(int*)(gEcShCupNearestObject + 0x68)) + 0x30))(
                        (u8)state->slotId);
                    if (state->slotId == buf[0])
                    {
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                    }
                }
            }
        }
    }
}

#pragma scheduling on
void ecsh_cup_release(void)
{
}

#pragma scheduling off
#pragma peephole off
void ecsh_cup_init(int obj, int def)
{
 /* #57 */
    int state;
    f32 dist;

    state = *(int*)&((GameObject*)obj)->extra;
    dist = lbl_803E5064;
    gEcShCupNearestObject = 0;
    ((EcshCupState*)state)->startPosX = ((GameObject*)obj)->anim.localPosX;
    ((EcshCupState*)state)->startPosY = ((GameObject*)obj)->anim.localPosY;
    ((EcshCupState*)state)->startPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((EcshCupState*)state)->spawnPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5084;
    {
        f32 fz = lbl_803E5068;
        ((EcshCupState*)state)->velX = fz;
        ((EcshCupState*)state)->velY = fz;
        ((EcshCupState*)state)->velZ = fz;
    }
    ((EcshCupState*)state)->currentMode = 0;
    ((EcshCupState*)state)->slotId = *(s16*)(def + 0x1a);
    ((EcshCupState*)state)->bobTimer = randomGetRange(0, 0x258);
    ((EcshCupState*)state)->spinRate = randomGetRange(-0x320, 0x320);
    *(u8*)&((EcshCupState*)state)->bobDir = 1;
    *(u8*)(obj + 0x37) = 0;
    ((EcshCupState*)state)->spawnTimer = lbl_803E5068;
    if (gEcShCupNearestObject == 0)
    {
        gEcShCupNearestObject = ObjGroup_FindNearestObject(0xb, obj, &dist);
    }
    ObjHits_EnableObject(obj);
    ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
    ObjHits_SyncObjectPositionIfDirty(obj);
}

#pragma scheduling on
#pragma peephole on
void ecsh_cup_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void fn_801C8B68(int obj)
{
    register int self = obj;
    register int state2 = *(int*)&((GameObject*)self)->anim.placementData;
    register int state = *(int*)&((GameObject*)self)->extra;
    GameObject* player = Obj_GetPlayerObject();
    ObjAnimEventList local_var;
    f32 dist;
    f32 angA, angB;
    int delta;

    if ((((GameObject*)self)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        ((GameObject*)self)->anim.rotX = 0;
        ((GameObject*)self)->anim.localPosY = *(float*)(state2 + 0xc);
        return;
    }

    *(short*)(state + 0xe) = (short)(
        (int)*(short*)(state + 0xe)
        + (int)(lbl_803E50A0 * timeDelta));
    *(short*)(state + 0x10) = (short)(
        (int)*(short*)(state + 0x10)
        + (int)(lbl_803E50A4 * timeDelta));
    *(short*)(state + 0x12) = (short)(
        (int)*(short*)(state + 0x12)
        + (int)(lbl_803E50A8 * timeDelta));

    ((GameObject*)self)->anim.localPosY = lbl_803E50AC + (*(float*)(state2 + 0xc) +
        mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0xe)) / gEcShCupAngleToRadDivisor));
    angA = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0x10)) / gEcShCupAngleToRadDivisor);
    angB = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0xe)) / gEcShCupAngleToRadDivisor);
    angB = angB + angA;
    *(s16*)&((GameObject*)self)->anim.rotZ = (lbl_803E50B8 * angB);
    angA = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0x12)) / gEcShCupAngleToRadDivisor);
    angB = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0xe)) / gEcShCupAngleToRadDivisor);
    angB = angB + angA;
    *(s16*)&((GameObject*)self)->anim.rotY = (lbl_803E50B8 * angB);

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(self, lbl_803E50BC, timeDelta,
                                                                 (ObjAnimEventList*)&local_var);

    if (player == NULL) return;

    {
        float dx = ((GameObject*)self)->anim.worldPosX - player->anim.worldPosX;
        float dz = ((GameObject*)self)->anim.worldPosZ - player->anim.worldPosZ;
        int ang = (u16)getAngle(dx, dz);
        delta = ang - (int)(u16)*(volatile s16*)&((GameObject*)self)->anim.rotX;
        if (delta > 0x8000) delta -= 0xffff;
        if (delta < -0x8000) delta += 0xffff;
        ((GameObject*)self)->anim.rotX = (short)(
            (int)((GameObject*)self)->anim.rotX
            + (int)((f32)delta * timeDelta / lbl_803E50C0));
    }
    dist = Vec_xzDistance((f32*)((u8*)self + 24), &player->anim.worldPosX);
    if (dist <= lbl_803E50C4)
    {
        ((GameObject*)self)->anim.alpha = (u8)(int)(lbl_803E50C8 * (dist / lbl_803E50C4));
    }
    else
    {
        ((GameObject*)self)->anim.alpha = 0xff;
    }
}
