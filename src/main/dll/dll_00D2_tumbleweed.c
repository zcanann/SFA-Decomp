/* DLL 0x00D2 (tumbleweed) - Tumbleweed and tumbleweed bush objects [0x80163BBC-0x801650D0). */
#include "main/dll/partfx_interface.h"
#include "main/dll/dll_00D1_tumbleweedbush.h"
#include "main/dll/dll_00D2_tumbleweed.h"
#include "main/audio/sfx_ids.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/gameloop_gamebit_api.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/dll/path_control_interface.h"
#include "main/obj_group.h"
#include "main/obj_list.h"
#include "main/obj_message.h"
#include "main/sky_interface.h"
#include "main/object_descriptor.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/track_dolphin_api.h"

u8 gTumbleweedCollisionPointData[8] = {0x41, 0xC8, 0, 0, 0, 0, 0, 0};

#define TUMBLEWEED_OBJFLAG_RENDERED 0x800
#define TRICKY_SEQID 0x24 /* retail "Tricky" (DLL 0xC4) */
#define TUMBLEWEED_MSG_IN_RANGE 0x7000a /* sent to player when grab is offered */
#define TUMBLEWEED_MSG_PICKUP   0x7000b /* player collected: award and burst */
#define TUMBLEWEED_OBJGROUP 3
#define TUMBLEWEED_OBJGROUP_SECONDARY 0x31


extern u8 gTumbleweedCollisionPoint[0xc];

void tumbleweed_updateRollingMotion(GameObject* obj, int state)
{
    int hitCount;
    u32 uval;
    TrackGroundHit** hitEntry;
    int i;
    int bestHit;
    f32 dy;
    f32 bestDy;
    f32 vp;
    TrackGroundHit** hitList[2];

    hitList[0] = 0x0;
    bestDy = 10000.0f;
    hitCount = hitDetectFn_80065e50(obj, obj->anim.localPosX, obj->anim.localPosY,
                                   obj->anim.localPosZ, hitList, 0, 0);
    for (i = 0, bestHit = 0, hitEntry = hitList[0]; i < hitCount; i++)
    {
        dy = obj->anim.localPosY - (*hitEntry)->height;
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
    if (obj->anim.velocityX > 1.0f)
    {
        obj->anim.velocityX = 1.0f;
    }
    else if (obj->anim.velocityX < -1.0f)
    {
        obj->anim.velocityX = -1.0f;
    }
    if (obj->anim.velocityY > 1.0f)
    {
        obj->anim.velocityY = 1.0f;
    }
    else if (obj->anim.velocityY < -1.0f)
    {
        obj->anim.velocityY = -1.0f;
    }
    if (obj->anim.velocityZ > 1.0f)
    {
        obj->anim.velocityZ = 1.0f;
    }
    else if (obj->anim.velocityZ < -1.0f)
    {
        obj->anim.velocityZ = -1.0f;
    }
    obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
    obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
    obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
    ((s16*)obj)[2] = (s16)((f32)(int) ((BackpackState*)state)->recoilVelX * timeDelta + (f32)(int)((s16*)obj)[2]);
    ((s16*)obj)[1] = (s16)((f32)(int) ((BackpackState*)state)->recoilVelZ * timeDelta + (f32)(int)((s16*)obj)[1]);
    *(s16*)obj = (s16)((f32)(int) * (s16*)(state + 0x280) * timeDelta + (f32)(int) * (s16*)obj);
    if (hitList[0] != 0x0)
    {
        if (obj->anim.localPosY > 7.0f + *(float*)hitList[0][bestHit])
        {
            obj->anim.velocityY += -0.17f;
        }
        else
        {
            obj->anim.localPosY = 7.0f + *(float*)hitList[0][bestHit];
            if (((short*)obj)[0x23] == 0x3fb)
            {
                dy = (f32)(int)(uval = randomGetRange(0x8c, 0xb4));
                dy = (f32) ((BackpackState*)state)->distToTarget / dy;
                vp = 0.8f * obj->anim.velocityY;
                obj->anim.velocityY = -(vp * dy);
            }
            else
            {
                dy = (f32)(int)(uval = randomGetRange(0x14, 0x28));
                dy = (f32) ((BackpackState*)state)->distToTarget / dy;
                vp = 0.8f * obj->anim.velocityY;
                obj->anim.velocityY = -(vp * dy);
            }
            bestHit = (int)(32.0f * obj->anim.velocityY);
            if (0x7f < bestHit)
            {
                bestHit = 0x7f;
            }
            if (0x10 < bestHit)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_mv_roothack16);
                uval = randomGetRange(0, 5);
                if (((int)uval == 0) && ((((BackpackState*)state)->flags & 8) != 0))
                {
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_id_27f);
                }
            }
        }
    }
    return;
}

void tumbleweed_func0F(GameObject *obj, int value)
{
    *(int*)&((BackpackState*)(obj)->extra)->targetObj = value;
}

int tumbleweed_func0E(GameObject *obj)
{
    return ((BackpackState*)(obj)->extra)->phase == TUMBLEWEED_PHASE_HOMING;
}

void tumbleweed_render2(int* obj, int targetPos)
{
    int* state = ((GameObject*)obj)->extra;
    f32 half;
    ((TumbleweedState*)state)->mode = TUMBLEWEED_PHASE_HOMING;
    *(int*)&((BackpackState*)state)->targetPos = targetPos;
    half = 0.5f;
    ((BackpackState*)state)->speed = timeDelta * half;
    ObjHits_DisableObject((GameObject*)obj);
}

void tumbleweed_modelMtxFn(GameObject *obj)
{
    int state = *(int*)&(obj)->extra;
    if (((TumbleweedState*)state)->mode == TUMBLEWEED_PHASE_ARMED)
    {
        ObjHits_EnableObject(obj);
        ((TumbleweedState*)state)->mode = TUMBLEWEED_PHASE_ROLLING;
        ((TumbleweedState*)state)->effectFlags |= 3;
        if ((obj)->anim.seqId == TUMBLEWEED_TYPE_4)
        {
            ((BackpackState*)state)->phaseTimer = 30.0f;
        }
    }
}

void tumbleweed_func0B(GameObject *obj, float x, float y)
{
    int extra = *(int*)&(obj)->extra;

    ((BackpackState*)extra)->anchorPosX = x;
    ((BackpackState*)extra)->anchorPosZ = y;
}

int tumbleweed_setScale(GameObject *obj)
{
    return ((BackpackState*)(obj)->extra)->phase;
}

int tumbleweed_getExtraSize(void)
{
    return 0x2a4;
}

void tumbleweed_free(int* obj)
{
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
    ObjGroup_RemoveObject((int)obj, TUMBLEWEED_OBJGROUP);
    ObjGroup_RemoveObject((int)obj, TUMBLEWEED_OBJGROUP_SECONDARY);
}

void tumbleweed_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if ((s32)visible >= 1) objRenderModelAndHitVolumes((GameObject*)p1, p2, p3, p4, p5, 1.0f);
}
void tumbleweed_updateStateMachine(GameObject* obj)
{
    int aux;
    int sphereIndex;
    u32 hitVolume;
    int hitObject;
    u32 popMsg;
    GameObject* player;
    GameObject* tricky;

    aux = *(int*)&obj->extra;
    {
        u32 state = ((BackpackState*)aux)->phase;
        if (state == TUMBLEWEED_PHASE_GROWING)
        {
            if (obj->anim.rootMotionScale < ((BackpackState*)aux)->targetScale)
            {
                obj->anim.rootMotionScale = ((BackpackState*)aux)->growRate * timeDelta + obj->anim.rootMotionScale;
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
                ObjHits_EnableObject(obj);
                ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_ROLLING;
                ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 3);
                if (obj->anim.seqId == TUMBLEWEED_TYPE_4)
                {
                    ((BackpackState*)aux)->phaseTimer = 30.0f;
                }
            }
        }
        else if (state == TUMBLEWEED_PHASE_ROLLING)
        {
            f32 dx, dz, dist2;
            f32 dist;
            player = (GameObject*)Obj_GetPlayerObject();
            dx = obj->anim.localPosX - player->anim.localPosX;
            dz = obj->anim.localPosZ - player->anim.localPosZ;
            dist2 = dx * dx + dz * dz;
            tricky = (GameObject*)getTrickyObject();
            if (tricky != 0 && tricky->anim.seqId == TRICKY_SEQID)
            {
                f32 ndx, ndz, ndist2;
                if (dist2 < 30625.0f)
                {
                    (*(int(**)(int, int, int, int))((char*)*tricky->anim.dll + 0x28))((int)tricky, (int)obj, 0, 1);
                }
                ndx = obj->anim.localPosX - tricky->anim.localPosX;
                ndz = obj->anim.localPosZ - tricky->anim.localPosZ;
                ndist2 = ndx * ndx + ndz * ndz;
                if (ndist2 < dist2)
                {
                    dx = ndx;
                    dz = ndz;
                    dist2 = ndist2;
                }
            }
            dist = sqrtf(dist2);
            ((BackpackState*)aux)->distToTarget = dist;
            {
                f32 dpx = obj->anim.localPosX - ((BackpackState*)aux)->anchorPosX;
                f32 dpz = obj->anim.localPosZ - ((BackpackState*)aux)->anchorPosZ;
                int dpdist = sqrtf(dpx * dpx + dpz * dpz);
                u32 dist;
                ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags & ~8);
                dist = ((BackpackState*)aux)->distToTarget;
                if ((f32)dist < 150.0f && dist != 0)
                {
                    f32 k;
                    obj->anim.velocityX = obj->anim.velocityX - dx / (15.0f * ((
                        f32)dist - 150.0f));
                    obj->anim.velocityZ = obj->anim.velocityZ - dz / (15.0f * ((
                        f32)(u32)((BackpackState*)aux)->distToTarget - 150.0f));
                    k = 728.0f;
                    ((BackpackState*)aux)->recoilVelX = k * obj->anim.velocityX;
                    ((BackpackState*)aux)->recoilVelZ = k * obj->anim.velocityZ;
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 8);
                }
                else
                {
                    u32 dpdi = (u16)dpdist;
                    if ((f32)dpdi > 10.0f && dpdi != 0)
                    {
                        f32 denom;
                        obj->anim.velocityX = obj->anim.velocityX - dpx / (denom = 10.0f * dpdi);
                        obj->anim.velocityZ = obj->anim.velocityZ - dpz / denom;
                    }
                }
            }
            tumbleweed_updateRollingMotion(obj, aux);
            (*gPathControlInterface)->advance((void*)obj, (void*)aux, timeDelta);
            ((BackpackState*)aux)->phaseTimer = ((BackpackState*)aux)->phaseTimer - timeDelta;
            if (((BackpackState*)aux)->phaseTimer < 0.0f)
            {
                ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
            }
            else
            {
                if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                    ((GameObject*)hitObject)->anim.seqId != obj->anim.seqId)
                {
                    if (obj->anim.seqId == TUMBLEWEED_TYPE_3)
                    {
                        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 3);
                        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags & ~0x10);
                        ((BackpackState*)aux)->phase = 3;
                        ((BackpackState*)aux)->growRate = 300.0f;
                        ((BackpackState*)aux)->phaseTimer = 1200.0f;
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
            f32 dist;
            player = (GameObject*)Obj_GetPlayerObject();
            dist = getXZDistance(&player->anim.worldPosX, &obj->anim.worldPosX);
            if (dist < 625.0f)
            {
                ((BackpackState*)aux)->triggerGameBit = 0x195;
                ((BackpackState*)aux)->pickupMsgValue = 0;
                ((BackpackState*)aux)->unk29C = 0.5f;
                ObjMsg_SendToObject(player, TUMBLEWEED_MSG_IN_RANGE, (void*)obj, (u32)(aux + 0x298));
                ((BackpackState*)aux)->phase = 4;
            }
            else
            {
                ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->growRate - timeDelta;
                ((BackpackState*)aux)->phaseTimer = ((BackpackState*)aux)->phaseTimer - timeDelta;
                if (((BackpackState*)aux)->phaseTimer < 0.0f)
                {
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                }
                else if (((BackpackState*)aux)->growRate <= 0.0f)
                {
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                }
                else
                {
                    if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                        ((GameObject*)hitObject)->anim.seqId != obj->anim.seqId)
                    {
                        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                    }
                }
            }
            tumbleweedbush_updateDetachedPiece(obj, (BackpackState*)aux);
            (*gPathControlInterface)->advance((void*)obj, (void*)aux, timeDelta);
        }
        else if (state == 4)
        {
            while (ObjMsg_Pop((void*)obj, &popMsg, 0, 0) != 0)
            {
                if (popMsg == TUMBLEWEED_MSG_PICKUP)
                {
                    gameBitIncrement(GAMEBIT_ITEM_FireWeed_Count);
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_lockoff22);
                    ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
                }
            }
        }
        else if (state == TUMBLEWEED_PHASE_HOMING)
        {
            f32* target = ((BackpackState*)aux)->targetPos;
            f32 vx, vy, vz, d;
            vx = target[0] - obj->anim.localPosX;
            vy = target[1] - obj->anim.localPosY;
            vz = target[2] - obj->anim.localPosZ;
            d = sqrtf(vx * vx + vy * vy + vz * vz);
            vx /= d;
            vy /= d;
            vz /= d;
            {
                f32 half;
                half = 0.5f;
                ((BackpackState*)aux)->speed = timeDelta * half + ((BackpackState*)aux)->speed;
            }
            {
                f32 k = 0.1f;
                f32 kv;
                kv = k * vx;
                obj->anim.velocityX = kv * ((BackpackState*)aux)->speed;
                kv = k * vy;
                obj->anim.velocityY = kv * ((BackpackState*)aux)->speed;
                kv = k * vz;
                obj->anim.velocityZ = kv * ((BackpackState*)aux)->speed;
            }
            d = getXZDistance((f32*)&obj->anim.localPosX, ((BackpackState*)aux)->targetPos);
            objMove((GameObject*)obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                    obj->anim.velocityZ * timeDelta);
            if (getXZDistance((f32*)&obj->anim.localPosX, ((BackpackState*)aux)->targetPos) > d)
            {
                f32 ldx, ldy, ldz;
                f32 half;
                ldx = (((BackpackState*)aux)->targetPos)[0] - obj->anim.localPosX;
                half = 0.5f;
                obj->anim.localPosX += ldx * half;
                ldy = (((BackpackState*)aux)->targetPos)[1] - obj->anim.localPosY;
                obj->anim.localPosY += ldy * half;
                ldz = (((BackpackState*)aux)->targetPos)[2] - obj->anim.localPosZ;
                obj->anim.localPosZ += ldz * half;
            }
        }
        else if (state == 7)
        {
            u32 j = 0;
            f32 k = 0.95f;
            for (; (s32)(j & 0xffff) < (s32)timeDelta; j = j + 1)
            {
                obj->anim.rootMotionScale = obj->anim.rootMotionScale * k;
            }
            obj->anim.localPosX = (((BackpackState*)aux)->targetPos)[0];
            obj->anim.localPosY = (((BackpackState*)aux)->targetPos)[1];
            obj->anim.localPosZ = (((BackpackState*)aux)->targetPos)[2];
        }
        else
        {
            if (((BackpackState*)aux)->growRate <= 0.0f)
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


void tumbleweed_updateTargetedStateMachine(GameObject *obj)
{
    int sphereIndex;
    u32 hitVolume;
    int hitObject;
    f32 sunTime;
    int aux;
    GameObject* player;
    u32 state;

    aux = *(int*)&(obj)->extra;
    state = ((BackpackState*)aux)->phase;
    if (state == TUMBLEWEED_PHASE_GROWING)
    {
        if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
        {
            if ((obj)->anim.rootMotionScale < ((BackpackState*)aux)->targetScale)
            {
                (obj)->anim.rootMotionScale = ((BackpackState*)aux)->growRate * timeDelta + (obj)->anim.rootMotionScale;
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
            f32 dx, dz, dist;
            player = ((BackpackState*)aux)->targetObj ? (GameObject*)((BackpackState*)aux)->targetObj
                                                      : (GameObject*)Obj_GetPlayerObject();
            dx = (obj)->anim.localPosX - player->anim.localPosX;
            dz = (obj)->anim.localPosZ - player->anim.localPosZ;
            dist = sqrtf(dx * dx + dz * dz);
            ((BackpackState*)aux)->distToTarget = dist;
            if (((BackpackState*)aux)->distToTarget < *(u16*)&((BackpackState*)aux)->triggerRange)
            {
                ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_ROLLING;
                *(u8*)&(obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&(obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
                ObjHits_EnableObject(obj);
            }
        }
    }
    else if (state == TUMBLEWEED_PHASE_ROLLING)
    {
        f32 dx, dz, d;
        u32 dist;
        player = ((BackpackState*)aux)->targetObj ? (GameObject*)((BackpackState*)aux)->targetObj
                                                  : (GameObject*)Obj_GetPlayerObject();
        dx = (obj)->anim.localPosX - player->anim.localPosX;
        dz = (obj)->anim.localPosZ - player->anim.localPosZ;
        d = sqrtf(dx * dx + dz * dz);
        ((BackpackState*)aux)->distToTarget = d;
        dist = ((BackpackState*)aux)->distToTarget;
        if ((f32)dist > 20.0f)
        {
            f32 k;
            (obj)->anim.velocityX = (obj)->anim.velocityX - dx / (20.0f * dist);
            (obj)->anim.velocityZ = (obj)->anim.velocityZ - dz / (20.0f * (f32)(u32)(
                (BackpackState*)aux)->distToTarget);
            k = 728.0f;
            ((BackpackState*)aux)->recoilVelX = k * (obj)->anim.velocityX;
            ((BackpackState*)aux)->recoilVelZ = k * (obj)->anim.velocityZ;
        }
        else
        {
            f32 k = 0.8f;
            (obj)->anim.velocityX = -(k * (obj)->anim.velocityX);
            (obj)->anim.velocityZ = -(k * (obj)->anim.velocityZ);
        }
        tumbleweed_updateRollingMotion(obj, aux);
        (*gPathControlInterface)->advance((void*)obj, (void*)aux, timeDelta);
        if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0)
        {
            mainSetBits(GAMEBIT_TumbleweedRelated642, 1);
            ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 7);
        }
    }
    else
    {
        if (((BackpackState*)aux)->growRate <= 0.0f)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->growRate - timeDelta;
        }
    }
}

void tumbleweed_updateEffects(GameObject *obj)
{
    TumbleweedState* state = (obj)->extra;
    int i;
    s16 type;

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_BURST) != 0)
    {
        switch ((obj)->anim.seqId)
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
        Sfx_PlayFromObject((int)obj, TUMBLEWEED_SFX_BURST);
        state->effectFlags = (u8)(state->effectFlags & ~TUMBLEWEED_EFFECT_FLAG_BURST);
    }

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_PUFF) != 0)
    {
        switch ((obj)->anim.seqId)
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
        (obj)->anim.alpha = 0;
        state->mode = TUMBLEWEED_PHASE_DESPAWNING;
        state->despawnTimer = 120.0f;
        ObjHits_DisableObject(obj);
        state->effectFlags = (u8)(state->effectFlags & ~TUMBLEWEED_EFFECT_FLAG_DESPAWN);
    }

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_HIT_PULSE) != 0 &&
        ((obj)->objectFlags & TUMBLEWEED_OBJFLAG_RENDERED) != 0)
    {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, TUMBLEWEED_HIT_PULSE_VOLUME_SLOT, 1, 0);
        if ((int)(u8)(++state->hitPulseCounter) % TUMBLEWEED_HIT_PULSE_PERIOD != 0)
        {
            fn_80098B18(obj, (obj)->anim.rootMotionScale, 1, 0, 0, NULL);
        }
        else
        {
            fn_80098B18(obj, (obj)->anim.rootMotionScale, 1, TUMBLEWEED_HIT_PULSE_ALT_STYLE, 0, NULL);
        }
        Sfx_KeepAliveLoopedObjectSound((int)obj, TUMBLEWEED_SFX_HIT_LOOP);
    }
}

void tumbleweed_update(GameObject *obj)
{
    if ((obj)->anim.seqId == TUMBLEWEED_TYPE_1)
    {
        tumbleweed_updateTargetedStateMachine(obj);
    }
    else
    {
        tumbleweed_updateStateMachine(obj);
    }
    tumbleweed_updateEffects(obj);
}

void tumbleweed_init(GameObject *obj, int defData)
{
    int aux = *(int*)&(obj)->extra;

    ((BackpackState*)aux)->anchorPosX = (obj)->anim.localPosX;
    ((BackpackState*)aux)->anchorPosZ = (obj)->anim.localPosZ;
    ((BackpackState*)aux)->triggerRange = (short)(2.0f * *(f32*)(defData + 0x1c));
    ((BackpackState*)aux)->variant = *(u8*)(defData + 0x1b);
    ((BackpackState*)aux)->targetScale = (obj)->anim.rootMotionScale;
    ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->targetScale / (f32)(s32)
    randomGetRange(0xc8, 0x1f4);
    ((BackpackState*)aux)->targetObj = 0;
    (obj)->anim.rootMotionScale = 0.001f;
    (*gPathControlInterface)->init((void*)aux, 0, 0x40000, 1);
    (*gPathControlInterface)->setLocalPointCollision((void*)aux, 1, gTumbleweedCollisionPoint, gTumbleweedCollisionPointData, 8);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)aux);
    ((BackpackState*)aux)->phase = TUMBLEWEED_PHASE_GROWING;
    ((BackpackState*)aux)->phaseTimer = 1200.0f + (f32)(s32)
    randomGetRange(-0x12c, 0x12c);
    ObjGroup_AddObject((int)obj, TUMBLEWEED_OBJGROUP);
    ObjGroup_AddObject((int)obj, TUMBLEWEED_OBJGROUP_SECONDARY);
    ObjHits_DisableObject(obj);
    ObjMsg_AllocQueue((void*)obj, 1);
    if ((obj)->anim.seqId == TUMBLEWEED_TYPE_3)
    {
        ((BackpackState*)aux)->flags = (u8)(((BackpackState*)aux)->flags | 0x10);
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

int lbl_803202E8[30] = {
    3, 3, 3, 3, 3, 3, 3, -1, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
};
u8 lbl_80320360[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
};
