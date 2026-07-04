/* DLL 0x00D2 (tumbleweed) — Tumbleweed and tumbleweed bush objects [0x80163BBC-0x801650D0). */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/effect_interfaces.h"
#include "main/gameplay_runtime.h"
#include "main/dll/backpack_state.h"
#include "main/dll/backpack.h"
#include "main/dll/path_control_interface.h"
#include "main/objlib.h"
#include "main/sky_interface.h"
#include "main/object_descriptor.h"

#define TUMBLEWEED_OBJFLAG_RENDERED 0x800
#define TUMBLEWEED_MSG_IN_RANGE 0x7000a /* sent to player when grab is offered */
#define TUMBLEWEED_MSG_PICKUP   0x7000b /* player collected: award and burst */
#define TUMBLEWEED_OBJGROUP 3
#define TUMBLEWEED_OBJGROUP_SECONDARY 0x31

extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int* hitsOut, int pointCount,
                                int mask);

extern f32 timeDelta;
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F60;
extern f32 lbl_803E2F64;
extern f32 lbl_803E2F68;
extern const f32 lbl_803E2F78;
extern const f32 lbl_803E2F7C;
extern const f32 lbl_803E2F80;
extern const f32 lbl_803E2F84;
extern const f32 lbl_803E2F88;
extern const f32 lbl_803E2F98;
extern const f32 lbl_803E2F9C;

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern const f32 lbl_803E2FC8;
extern const f32 lbl_803E2FCC;
extern const f32 lbl_803E2FD0;
extern const f32 lbl_803E2FB4;
extern u8 gTumbleweedCollisionPointData[8];
extern u8 gTumbleweedCollisionPoint[0xc];
extern void Obj_FreeObject(int obj);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern f32 getXZDistance(f32* a, f32* b);
extern int gameBitIncrement(int bit);
extern void fn_80163990(int obj, int aux);
extern const f32 lbl_803E2FA0;
extern const f32 lbl_803E2FAC;
extern const f32 lbl_803E2FB0;
extern const f32 lbl_803E2FB8;
extern const f32 lbl_803E2FBC;
extern const f32 lbl_803E2FC0;
extern f32 sqrtf(f32 x);

void tumbleweed_updateRollingMotion(int obj, int state)
{
    int hitCount;
    u32 uval;
    u32* hitEntry;
    int i;
    int bestHit;
    f32 dy;
    f32 bestDy;
    f32 vp;
    u32* hitList[2];

    hitList[0] = 0x0;
    bestDy = lbl_803E2F78;
    hitCount = hitDetectFn_80065e50(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, obj, (int*)hitList, 0, 0);
    for (i = 0, bestHit = 0, hitEntry = hitList[0]; i < hitCount; i++)
    {
        dy = ((GameObject*)obj)->anim.localPosY - *(float*)*hitEntry;
        if (dy < 0.0f)
        {
            dy = -1.0f * dy + 10.0f;
        }
        if (dy < bestDy)
        {
            bestHit = i;
            bestDy = dy;
        }
        hitEntry = hitEntry + 1;
    }
    if (((GameObject*)obj)->anim.velocityX > lbl_803E2F80)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E2F80;
    }
    else if (((GameObject*)obj)->anim.velocityX < *(f32*)&lbl_803E2F7C)
    {
        ((GameObject*)obj)->anim.velocityX = *(f32*)&lbl_803E2F7C;
    }
    if (((GameObject*)obj)->anim.velocityY > lbl_803E2F80)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2F80;
    }
    else if (((GameObject*)obj)->anim.velocityY < lbl_803E2F7C)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2F7C;
    }
    if (((GameObject*)obj)->anim.velocityZ > lbl_803E2F80)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E2F80;
    }
    else if (((GameObject*)obj)->anim.velocityZ < lbl_803E2F7C)
    {
        ((GameObject*)obj)->anim.velocityZ = lbl_803E2F7C;
    }
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.localPosZ;
    ((s16*)obj)[2] = (s16)((f32)(int) ((BackpackState*)state)->recoilVelX * timeDelta + (f32)(int)((s16*)obj)[2]);
    ((s16*)obj)[1] = (s16)((f32)(int) ((BackpackState*)state)->recoilVelZ * timeDelta + (f32)(int)((s16*)obj)[1]);
    *(s16*)obj = (s16)((f32)(int) * (s16*)(state + 0x280) * timeDelta + (f32)(int) * (s16*)obj);
    if (hitList[0] != 0x0)
    {
        if (((GameObject*)obj)->anim.localPosY > lbl_803E2F60 + *(float*)hitList[0][bestHit])
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2F64;
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E2F60 + *(float*)hitList[0][bestHit];
            if (((short*)obj)[0x23] == 0x3fb)
            {
                dy = (f32)(int)(uval = randomGetRange(0x8c, 0xb4));
                dy = (f32) ((BackpackState*)state)->distToTarget / dy;
                vp = lbl_803E2F84 * ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)obj)->anim.velocityY = -(vp * dy);
            }
            else
            {
                dy = (f32)(int)(uval = randomGetRange(0x14, 0x28));
                dy = (f32) ((BackpackState*)state)->distToTarget / dy;
                vp = lbl_803E2F84 * ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)obj)->anim.velocityY = -(vp * dy);
            }
            bestHit = (int)(lbl_803E2F88 * ((GameObject*)obj)->anim.velocityY);
            if (0x7f < bestHit)
            {
                bestHit = 0x7f;
            }
            if (0x10 < bestHit)
            {
                Sfx_PlayFromObject(obj, SFXsc_gethit02);
                uval = randomGetRange(0, 5);
                if (((int)uval == 0) && ((((BackpackState*)state)->flags & 8) != 0))
                {
                    Sfx_PlayFromObject(obj, SFXsc_gethit03);
                }
            }
        }
    }
    return;
}

void tumbleweed_func0F(int obj, int value)
{
    *(int*)&((BackpackState*)((GameObject*)obj)->extra)->targetObj = value;
}

int tumbleweed_func0E(int obj)
{
    return ((BackpackState*)((GameObject*)obj)->extra)->phase == TUMBLEWEED_PHASE_HOMING;
}

void tumbleweed_render2(int* obj, int p2)
{
    int* state = ((GameObject*)obj)->extra;
    ((TumbleweedState*)state)->mode = TUMBLEWEED_PHASE_HOMING;
    *(int*)&((BackpackState*)state)->targetPos = p2;
    ((BackpackState*)state)->speed = timeDelta * lbl_803E2F98;
    ObjHits_DisableObject((u32)obj);
}

void tumbleweed_modelMtxFn(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (((TumbleweedState*)state)->mode == TUMBLEWEED_PHASE_ARMED)
    {
        ObjHits_EnableObject((u32)obj);
        ((TumbleweedState*)state)->mode = TUMBLEWEED_PHASE_ROLLING;
        ((TumbleweedState*)state)->effectFlags |= 3;
        if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_4)
        {
            ((BackpackState*)state)->phaseTimer = lbl_803E2F9C;
        }
    }
}

void tumbleweed_func0B(int obj, float x, float y)
{
    int extra = *(int*)&((GameObject*)obj)->extra;

    ((BackpackState*)extra)->anchorPosX = x;
    ((BackpackState*)extra)->anchorPosZ = y;
}

int tumbleweed_setScale(int obj)
{
    return ((BackpackState*)((GameObject*)obj)->extra)->phase;
}

int tumbleweed_getExtraSize(void)
{
    return 0x2a4;
}

void tumbleweed_free(int* obj)
{
    extern void ObjGroup_RemoveObject(int* obj, int group); /* #57 */
    int* items;
    int counter;
    int limit;
    int target_id;

    switch (((GameObject*)obj)->anim.seqId)
    {
    case TUMBLEWEED_TYPE_1:
        target_id = 0x28d;
        break;
    case 0x3fb:
        target_id = 0x3fd;
        break;
    case TUMBLEWEED_TYPE_3:
        target_id = 0x4b9;
        break;
    case TUMBLEWEED_TYPE_4:
        target_id = 0x4be;
        break;
    }

    items = ObjList_GetObjects(&counter, &limit);
    while (counter < limit)
    {
        GameObject* o = (GameObject*)items[counter];
        if (target_id == o->anim.seqId)
        {
            (*(VtableFn*)(**(int**)((int)o + 0x68) + 0x20))(o, obj);
        }
        counter = counter + 1;
    }
    ObjGroup_RemoveObject(obj, TUMBLEWEED_OBJGROUP);
    ObjGroup_RemoveObject(obj, TUMBLEWEED_OBJGROUP_SECONDARY);
}

void tumbleweed_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32); /* #57 */
    if ((s32)visible >= 1) objRenderFn_8003b8f4(lbl_803E2F80);
}

void tumbleweed_update(int obj)
{
    if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_1)
    {
        tumbleweed_updateTargetedStateMachine(obj);
    }
    else
    {
        tumbleweed_updateStateMachine(obj);
    }
    tumbleweed_updateEffects(obj);
}

void tumbleweed_updateStateMachine(int obj)
{
    extern void tumbleweed_updateRollingMotion(int obj, int aux); /* #57 */
    int aux;
    int sphereIndex;
    u32 hitVolume;
    int hitObject;
    u32 popMsg;
    GameObject* player;
    GameObject* tricky;

    aux = *(int*)&((GameObject*)obj)->extra;
    {
        u32 state = ((BackpackState*)aux)->phase;
        if (state == TUMBLEWEED_PHASE_GROWING)
        {
            if (((GameObject*)obj)->anim.rootMotionScale < ((BackpackState*)aux)->targetScale)
            {
                ((GameObject*)obj)->anim.rootMotionScale = ((BackpackState*)aux)->growRate * timeDelta + ((GameObject*)
                    obj)->anim.rootMotionScale;
            }
            else
            {
                ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_ARMED;
            }
        }
        else if (state == TUMBLEWEED_PHASE_ARMED)
        {
            if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0)
            {
                ObjHits_EnableObject((u32)obj);
                ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_ROLLING;
                ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 3);
                if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_4)
                {
                    ((BackpackState*)aux)->phaseTimer = lbl_803E2F9C;
                }
            }
        }
        else if (state == TUMBLEWEED_PHASE_ROLLING)
        {
            f32 dx, dz, dist2;
            f32 d;
            player = (GameObject*)Obj_GetPlayerObject();
            dx = ((GameObject*)obj)->anim.localPosX - player->anim.localPosX;
            dz = ((GameObject*)obj)->anim.localPosZ - player->anim.localPosZ;
            dist2 = dx * dx + dz * dz;
            tricky = (GameObject*)getTrickyObject();
            if (tricky != 0 && tricky->anim.seqId == 0x24)
            {
                f32 ndx, ndz, ndist2;
                if (dist2 < lbl_803E2FA0)
                {
                    (*(int(**)(int, int, int, int))((char*)*tricky->anim.dll + 0x28))((int)tricky, obj, 0, 1);
                }
                ndx = ((GameObject*)obj)->anim.localPosX - tricky->anim.localPosX;
                ndz = ((GameObject*)obj)->anim.localPosZ - tricky->anim.localPosZ;
                ndist2 = ndx * ndx + ndz * ndz;
                if (ndist2 < dist2)
                {
                    dx = ndx;
                    dz = ndz;
                    dist2 = ndist2;
                }
            }
            d = sqrtf(dist2);
            *(s16*)&((BackpackState*)aux)->distToTarget = d;
            {
                f32 dpx = ((GameObject*)obj)->anim.localPosX - ((BackpackState*)aux)->anchorPosX;
                f32 dpz = ((GameObject*)obj)->anim.localPosZ - ((BackpackState*)aux)->anchorPosZ;
                int dpdist = sqrtf(dpx * dpx + dpz * dpz);
                u32 dist;
                ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags & ~8);
                dist = ((BackpackState*)aux)->distToTarget;
                if ((f32)dist < 150.0f && dist != 0)
                {
                    f32 k;
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - dx / (15.0f * ((
                        f32)dist - 150.0f));
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - dz / (15.0f * ((
                        f32)(u32)((BackpackState*)aux)->distToTarget - 150.0f));
                    k = lbl_803E2FAC;
                    ((BackpackState*)aux)->recoilVelX = k * ((GameObject*)obj)->anim.velocityX;
                    ((BackpackState*)aux)->recoilVelZ = k * ((GameObject*)obj)->anim.velocityZ;
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 8);
                }
                else
                {
                    u32 dpdi = (u16)dpdist;
                    if ((f32)dpdi > lbl_803E2F5C && dpdi != 0)
                    {
                        f32 denom = lbl_803E2F5C * dpdi;
                        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - dpx / denom;
                        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - dpz / denom;
                    }
                }
            }
            tumbleweed_updateRollingMotion(obj, aux);
            (*gPathControlInterface)->advance((void*)obj, (void*)aux, timeDelta);
            ((BackpackState*)aux)->phaseTimer = ((BackpackState*)aux)->phaseTimer - timeDelta;
            if (((BackpackState*)aux)->phaseTimer < lbl_803E2F68)
            {
                ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
            }
            else
            {
                if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                    ((GameObject*)hitObject)->anim.seqId != ((GameObject*)obj)->anim.seqId)
                {
                    if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_3)
                    {
                        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 3);
                        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags & ~0x10);
                        ((BackpackState*)aux)->phase = 3;
                        ((BackpackState*)aux)->growRate = lbl_803E2FB0;
                        ((BackpackState*)aux)->phaseTimer = lbl_803E2FB4;
                        Obj_SetActiveModelIndex(obj, 1);
                    }
                    else
                    {
                        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                    }
                }
            }
        }
        else if (state == 3)
        {
            f32 d;
            player = (GameObject*)Obj_GetPlayerObject();
            d = getXZDistance(&player->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
            if (d < lbl_803E2FB8)
            {
                ((BackpackState*)aux)->unk298 = 0x195;
                ((BackpackState*)aux)->unk29A = 0;
                ((BackpackState*)aux)->unk29C = lbl_803E2F98;
                ObjMsg_SendToObject(player, TUMBLEWEED_MSG_IN_RANGE, (void*)obj, (u32)(aux + 0x298));
                ((BackpackState*)aux)->phase = 4;
            }
            else
            {
                ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->growRate - timeDelta;
                ((BackpackState*)aux)->phaseTimer = ((BackpackState*)aux)->phaseTimer - timeDelta;
                if (((BackpackState*)aux)->phaseTimer < lbl_803E2F68)
                {
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                }
                else if (((BackpackState*)aux)->growRate <= lbl_803E2F68)
                {
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                }
                else
                {
                    if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                        ((GameObject*)hitObject)->anim.seqId != ((GameObject*)obj)->anim.seqId)
                    {
                        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                    }
                }
                fn_80163990(obj, aux);
                (*gPathControlInterface)->advance((void*)obj, (void*)aux, timeDelta);
            }
        }
        else if (state == 4)
        {
            extern int ObjMsg_Pop(void *obj, u32 *outMessage, u32 *outSender, u32 *outParam);

            while (ObjMsg_Pop((void*)obj, &popMsg, 0, 0) != 0)
            {
                if (popMsg == TUMBLEWEED_MSG_PICKUP)
                {
                    gameBitIncrement(0x194);
                    Sfx_PlayFromObject(obj, SFXen_treadlpc);
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                }
            }
        }
        else if (state == TUMBLEWEED_PHASE_HOMING)
        {
            f32* target = ((BackpackState*)aux)->targetPos;
            f32 vx, vy, vz, d;
            vx = target[0] - ((GameObject*)obj)->anim.localPosX;
            vy = target[1] - ((GameObject*)obj)->anim.localPosY;
            vz = target[2] - ((GameObject*)obj)->anim.localPosZ;
            d = sqrtf(vx * vx + vy * vy + vz * vz);
            vx /= d;
            vy /= d;
            vz /= d;
            ((BackpackState*)aux)->speed = timeDelta * lbl_803E2F98 + ((BackpackState*)aux)->speed;
            {
                f32 k = lbl_803E2FBC;
                f32 kv;
                kv = k * vx;
                ((GameObject*)obj)->anim.velocityX = kv * ((BackpackState*)aux)->speed;
                kv = k * vy;
                ((GameObject*)obj)->anim.velocityY = kv * ((BackpackState*)aux)->speed;
                kv = k * vz;
                ((GameObject*)obj)->anim.velocityZ = kv * ((BackpackState*)aux)->speed;
            }
            d = getXZDistance((f32*)(obj + 0xc), ((BackpackState*)aux)->targetPos);
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            if (getXZDistance((f32*)(obj + 0xc), ((BackpackState*)aux)->targetPos) > d)
            {
                f32 ldx, ldy, ldz;
                ldx = (((BackpackState*)aux)->targetPos)[0] - ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)obj)->anim.localPosX += ldx * lbl_803E2F98;
                ldy = (((BackpackState*)aux)->targetPos)[1] - ((GameObject*)obj)->anim.localPosY;
                ((GameObject*)obj)->anim.localPosY += ldy * lbl_803E2F98;
                ldz = (((BackpackState*)aux)->targetPos)[2] - ((GameObject*)obj)->anim.localPosZ;
                ((GameObject*)obj)->anim.localPosZ += ldz * lbl_803E2F98;
            }
        }
        else if (state == 7)
        {
            u32 j = 0;
            f32 k = lbl_803E2FC0;
            for (; (s32)(j & 0xffff) < (s32)timeDelta; j = j + 1)
            {
                ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * k;
            }
            ((GameObject*)obj)->anim.localPosX = (((BackpackState*)aux)->targetPos)[0];
            ((GameObject*)obj)->anim.localPosY = (((BackpackState*)aux)->targetPos)[1];
            ((GameObject*)obj)->anim.localPosZ = (((BackpackState*)aux)->targetPos)[2];
        }
        else
        {
            if (((BackpackState*)aux)->growRate <= lbl_803E2F68)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->growRate - timeDelta;
            }
        }
    }
}

void tumbleweed_init(int obj, int defData)
{
    int aux = *(int*)&((GameObject*)obj)->extra;

    ((BackpackState*)aux)->anchorPosX = ((GameObject*)obj)->anim.localPosX;
    ((BackpackState*)aux)->anchorPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((BackpackState*)aux)->triggerRange = (short)(lbl_803E2FCC * *(f32*)(defData + 0x1c));
    ((BackpackState*)aux)->unk279 = *(u8*)(defData + 0x1b);
    ((BackpackState*)aux)->targetScale = ((GameObject*)obj)->anim.rootMotionScale;
    ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->targetScale / (f32)(s32)
    randomGetRange(0xc8, 0x1f4);
    *(u32*)&((BackpackState*)aux)->targetObj = 0;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E2FD0;
    (*gPathControlInterface)->init((void*)aux, 0, 0x40000, 1);
    (*gPathControlInterface)->setLocalPointCollision((void*)aux, 1, gTumbleweedCollisionPoint, gTumbleweedCollisionPointData, 8);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)aux);
    ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_GROWING;
    ((BackpackState*)aux)->phaseTimer = lbl_803E2FB4 + (f32)(s32)
    randomGetRange(-0x12c, 0x12c);
    ObjGroup_AddObject(obj, TUMBLEWEED_OBJGROUP);
    ObjGroup_AddObject(obj, TUMBLEWEED_OBJGROUP_SECONDARY);
    ObjHits_DisableObject((u32)obj);
    ObjMsg_AllocQueue((void*)obj, 1);
    if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_3)
    {
        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 0x10);
    }
}

void tumbleweed_updateEffects(int obj)
{
    TumbleweedState* state = ((GameObject*)obj)->extra;
    int i;
    s16 type;

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_BURST) != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case TUMBLEWEED_TYPE_3:
        case TUMBLEWEED_TYPE_1:
        case TUMBLEWEED_TYPE_4:
            i = TUMBLEWEED_EFFECT_SPAWN_COUNT;
            do
            {
                (*gPartfxInterface)->spawnObject(
                    (void*)obj, TUMBLEWEED_EFFECT_BURST_SPECIAL, NULL,
                    TUMBLEWEED_PARTFX_MODE_ACTIVE, -1, NULL);
                i = i - 1;
            }
            while (i != 0);
            break;
        default:
            i = TUMBLEWEED_EFFECT_SPAWN_COUNT;
            do
            {
                (*gPartfxInterface)->spawnObject(
                    (void*)obj, TUMBLEWEED_EFFECT_BURST_DEFAULT, NULL,
                    TUMBLEWEED_PARTFX_MODE_ACTIVE, -1, NULL);
                i = i - 1;
            }
            while (i != 0);
            break;
        }
        Sfx_PlayFromObject(obj, TUMBLEWEED_SFX_BURST);
        state->effectFlags = (u8)(state->effectFlags & ~TUMBLEWEED_EFFECT_FLAG_BURST);
    }

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_PUFF) != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case TUMBLEWEED_TYPE_3:
        case TUMBLEWEED_TYPE_1:
        case TUMBLEWEED_TYPE_4:
            (*gPartfxInterface)->spawnObject(
                (void*)obj, TUMBLEWEED_EFFECT_PUFF_SPECIAL, NULL,
                TUMBLEWEED_PARTFX_MODE_ACTIVE, -1, NULL);
            break;
        default:
            (*gPartfxInterface)->spawnObject(
                (void*)obj, TUMBLEWEED_EFFECT_PUFF_DEFAULT, NULL,
                TUMBLEWEED_PARTFX_MODE_ACTIVE, -1, NULL);
            break;
        }
        state->effectFlags = (u8)(state->effectFlags & ~TUMBLEWEED_EFFECT_FLAG_PUFF);
    }

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_DESPAWN) != 0)
    {
        ((GameObject*)obj)->anim.alpha = 0;
        state->mode = TUMBLEWEED_PHASE_DESPAWNING;
        state->despawnTimer = lbl_803E2FC8;
        ObjHits_DisableObject((u32)obj);
        state->effectFlags = (u8)(state->effectFlags & ~TUMBLEWEED_EFFECT_FLAG_DESPAWN);
    }

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_HIT_PULSE) != 0 &&
        (((GameObject*)obj)->objectFlags & TUMBLEWEED_OBJFLAG_RENDERED) != 0)
    {
        ObjHits_SetHitVolumeSlot((u32)obj, TUMBLEWEED_HIT_PULSE_VOLUME_SLOT, 1, 0);
        if ((int)(u8)(++state->hitPulseCounter) % TUMBLEWEED_HIT_PULSE_PERIOD != 0)
        {
            fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 1, 0, 0, 0);
        }
        else
        {
            fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 1, TUMBLEWEED_HIT_PULSE_ALT_STYLE, 0, 0);
        }
        Sfx_KeepAliveLoopedObjectSound(obj, TUMBLEWEED_SFX_HIT_LOOP);
    }
}

void tumbleweed_updateTargetedStateMachine(int obj)
{
    extern void tumbleweed_updateRollingMotion(int obj, int aux); /* #57 */
    int sphereIndex;
    u32 hitVolume;
    int hitObject;
    f32 sunTime;
    int aux;
    GameObject* player;
    u32 state;

    aux = *(int*)&((GameObject*)obj)->extra;
    state = ((BackpackState*)aux)->phase;
    if (state == TUMBLEWEED_PHASE_GROWING)
    {
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
        {
            if (((GameObject*)obj)->anim.rootMotionScale < ((BackpackState*)aux)->targetScale)
            {
                ((GameObject*)obj)->anim.rootMotionScale = ((BackpackState*)aux)->growRate * timeDelta + ((GameObject*)
                    obj)->anim.rootMotionScale;
            }
            else
            {
                ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_ARMED;
            }
        }
    }
    else if (state == TUMBLEWEED_PHASE_ARMED)
    {
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
        {
            f32 dx, dz, d;
            player = ((BackpackState*)aux)->targetObj ? (GameObject*)((BackpackState*)aux)->targetObj
                                                      : (GameObject*)Obj_GetPlayerObject();
            dx = ((GameObject*)obj)->anim.localPosX - player->anim.localPosX;
            dz = ((GameObject*)obj)->anim.localPosZ - player->anim.localPosZ;
            d = sqrtf(dx * dx + dz * dz);
            *(s16*)&((BackpackState*)aux)->distToTarget = d;
            if (((BackpackState*)aux)->distToTarget < *(u16*)&((BackpackState*)aux)->triggerRange)
            {
                ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_ROLLING;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
                ObjHits_EnableObject((u32)obj);
            }
        }
    }
    else if (state == TUMBLEWEED_PHASE_ROLLING)
    {
        f32 dx, dz, d;
        u32 dist;
        player = ((BackpackState*)aux)->targetObj ? (GameObject*)((BackpackState*)aux)->targetObj
                                                  : (GameObject*)Obj_GetPlayerObject();
        dx = ((GameObject*)obj)->anim.localPosX - player->anim.localPosX;
        dz = ((GameObject*)obj)->anim.localPosZ - player->anim.localPosZ;
        d = sqrtf(dx * dx + dz * dz);
        *(s16*)&((BackpackState*)aux)->distToTarget = d;
        dist = ((BackpackState*)aux)->distToTarget;
        if ((f32)dist > 20.0f)
        {
            f32 k;
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - dx / (20.0f * dist);
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - dz / (20.0f * (f32)(u32)(
                (BackpackState*)aux)->distToTarget);
            k = lbl_803E2FAC;
            ((BackpackState*)aux)->recoilVelX = k * ((GameObject*)obj)->anim.velocityX;
            ((BackpackState*)aux)->recoilVelZ = k * ((GameObject*)obj)->anim.velocityZ;
        }
        else
        {
            f32 k = lbl_803E2F84;
            ((GameObject*)obj)->anim.velocityX = -(k * ((GameObject*)obj)->anim.velocityX);
            ((GameObject*)obj)->anim.velocityZ = -(k * ((GameObject*)obj)->anim.velocityZ);
        }
        tumbleweed_updateRollingMotion(obj, aux);
        (*gPathControlInterface)->advance((void*)obj, (void*)aux, timeDelta);
        if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0)
        {
            GameBit_Set(0x642, 1);
            ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
        }
    }
    else
    {
        if (((BackpackState*)aux)->growRate <= lbl_803E2F68)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->growRate - timeDelta;
        }
    }
}

u8 gTumbleweedCollisionPoint[0xc] = { 0 };

ObjectDescriptor16WithPadding gTumbleweedObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_16_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)tumbleweed_init,
        (ObjectDescriptorCallback)tumbleweed_update,
        0,
        (ObjectDescriptorCallback)tumbleweed_render,
        (ObjectDescriptorCallback)tumbleweed_free,
        0,
        tumbleweed_getExtraSize,
        (ObjectDescriptorCallback)tumbleweed_setScale,
        (ObjectDescriptorCallback)tumbleweed_func0B,
        (ObjectDescriptorCallback)tumbleweed_modelMtxFn,
        (ObjectDescriptorCallback)tumbleweed_render2,
        (ObjectDescriptorCallback)tumbleweed_func0E,
        (ObjectDescriptorCallback)tumbleweed_func0F,
    },
    0,
};
