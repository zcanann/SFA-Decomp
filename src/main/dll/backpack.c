#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/dll/baddie_state.h"
#include "main/dll/backpack_state.h"
#include "main/dll/backpack.h"
#include "main/dll/landedArwing.h"
#include "main/dll/path_control_interface.h"
#include "main/objanim.h"
#include "main/objlib.h"
#include "main/objhits_types.h"

typedef struct LandedArwingTriggerLaunchTargetState
{
    u8 pad0[0x3F0 - 0x0];
    s16 unk3F0;
    s16 unk3F2;
    u8 pad3F4[0x405 - 0x3F4];
    u8 unk405;
    u8 pad406[0x408 - 0x406];
} LandedArwingTriggerLaunchTargetState;


extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

extern void* gBaddieControlInterface;
extern void* gPlayerInterface;
extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E2FC8;
extern f32 lbl_803E2FCC;
extern f32 lbl_803E2FD0;
extern f32 lbl_803E2FB4;
extern u8 lbl_803DBD40[8];
extern u8 lbl_80320288[0xc];

extern void Obj_FreeObject(int obj);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern f32 getXZDistance(f32 * p1, f32 * p2);
extern void gameBitIncrement(int eventId);
extern void tumbleweed_updateRollingMotion(int obj, int aux);
extern void fn_80163990(int obj, int aux);
extern void fn_80165B3C(int obj, int state);
extern void landedarwing_moveSurfaceCrawler(int obj, int state);
extern void fn_80166444(int obj, int state);
extern void updateConstrainedChaseVelocity(int obj, f32 x, f32 y, f32 z, f32 scale);

extern void* gSHthorntailAnimationInterface;
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F84;
extern f32 lbl_803E2F68;
extern f32 lbl_803E2F98;
extern f32 lbl_803E2F9C;
extern f32 lbl_803E2FA0;
extern f32 lbl_803E2FA4;
extern f32 lbl_803E2FA8;
extern f32 lbl_803E2FAC;
extern f32 lbl_803E2FB0;
extern f32 lbl_803E2FB8;
extern f32 lbl_803E2FBC;
extern f32 lbl_803E2FC0;
extern f32 lbl_803E2FC4;
extern f64 lbl_803E2F90;
extern f32 lbl_803E2FD8;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E2FE0;
extern f32 lbl_803E2FE4;
extern f32 lbl_803E2FE8;
extern f32 lbl_803E2FEC;
extern f32 lbl_803E2FF0;
extern f32 lbl_803E2FF4;
extern f32 lbl_803E2FF8;
extern f32 lbl_803E2FFC;
extern f32 lbl_803E3000;

extern f32 sqrtf(f32 x);

/*
 * --INFO--
 *
 * Function: tumbleweed_update
 * EN v1.0 Address: 0x80164EE4
 * EN v1.0 Size: 72b
 */
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

/* 8b "li r3, N; blr" returners. */
int LandedArwing_ReturnZero(void) { return 0x0; }

/*
 * --INFO--
 *
 * Function: tumbleweed_updateStateMachine
 * EN v1.0 Address: 0x801641B0
 * EN v1.0 Size: 1936b
 */
void tumbleweed_updateStateMachine(int obj)
{
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
        if (state == 0)
        {
            if (((GameObject*)obj)->anim.rootMotionScale < ((BackpackState*)aux)->targetScale)
            {
                ((GameObject*)obj)->anim.rootMotionScale = ((BackpackState*)aux)->growRate * timeDelta + ((GameObject*)
                    obj)->anim.rootMotionScale;
            }
            else
            {
                ((BackpackState*)aux)->phase = 1;
            }
        }
        else if (state == 1)
        {
            if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0)
            {
                ObjHits_EnableObject(obj);
                ((BackpackState*)aux)->phase = 2;
                ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 3);
                if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_4)
                {
                    ((BackpackState*)aux)->phaseTimer = lbl_803E2F9C;
                }
            }
        }
        else if (state == 2)
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
            *(s16*)&((BackpackState*)aux)->unk268 = d;
            {
                f32 dpx = ((GameObject*)obj)->anim.localPosX - ((BackpackState*)aux)->unk288;
                f32 dpz = ((GameObject*)obj)->anim.localPosZ - ((BackpackState*)aux)->unk28C;
                int dpdist = sqrtf(dpx * dpx + dpz * dpz);
                u32 dist;
                ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A & ~8);
                dist = ((BackpackState*)aux)->unk268;
                if ((f32)dist < lbl_803E2FA4 && dist != 0)
                {
                    f32 k;
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - dx / (lbl_803E2FA8 * ((
                        f32)dist - lbl_803E2FA4));
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - dz / (lbl_803E2FA8 * ((
                        f32)(u32)((BackpackState*)aux)->unk268 - lbl_803E2FA4));
                    k = lbl_803E2FAC;
                    ((BackpackState*)aux)->unk27C = k * ((GameObject*)obj)->anim.velocityX;
                    ((BackpackState*)aux)->unk27E = k * ((GameObject*)obj)->anim.velocityZ;
                    ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 8);
                }
                else
                {
                    u32 dpdi = (u16)dpdist;
                    if ((f32)dpdi > lbl_803E2F5C && dpdi != 0)
                    {
                        f32 denom = lbl_803E2F5C * (f32)dpdi;
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
                ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 7);
            }
            else
            {
                if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                    ((GameObject*)hitObject)->anim.seqId != ((GameObject*)obj)->anim.seqId)
                {
                    if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_3)
                    {
                        ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 3);
                        ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A & ~0x10);
                        ((BackpackState*)aux)->phase = 3;
                        ((BackpackState*)aux)->growRate = lbl_803E2FB0;
                        ((BackpackState*)aux)->phaseTimer = lbl_803E2FB4;
                        Obj_SetActiveModelIndex(obj, 1);
                    }
                    else
                    {
                        ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 7);
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
                ObjMsg_SendToObject(player, 0x7000a, (void*)obj, (uint)(aux + 0x298));
                ((BackpackState*)aux)->phase = 4;
            }
            else
            {
                ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->growRate - timeDelta;
                ((BackpackState*)aux)->phaseTimer = ((BackpackState*)aux)->phaseTimer - timeDelta;
                if (((BackpackState*)aux)->phaseTimer < lbl_803E2F68)
                {
                    ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 7);
                }
                else if (((BackpackState*)aux)->growRate <= lbl_803E2F68)
                {
                    ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 7);
                }
                else
                {
                    if (ObjHits_GetPriorityHit(obj, &hitObject, &sphereIndex, &hitVolume) != 0 &&
                        ((GameObject*)hitObject)->anim.seqId != ((GameObject*)obj)->anim.seqId)
                    {
                        ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 7);
                    }
                }
                fn_80163990(obj, aux);
                (*gPathControlInterface)->advance((void*)obj, (void*)aux, timeDelta);
            }
        }
        else if (state == 4)
        {
            while (ObjMsg_Pop((void*)obj, &popMsg, (u32*)0, (u32*)0) != 0)
            {
                if (popMsg == 0x7000b)
                {
                    gameBitIncrement(0x194);
                    Sfx_PlayFromObject(obj, SFXen_treadlpc);
                    ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 7);
                }
            }
        }
        else if (state == 6)
        {
            f32* target = ((BackpackState*)aux)->unk290;
            f32 vx, vy, vz, d;
            vx = target[0] - ((GameObject*)obj)->anim.localPosX;
            vy = target[1] - ((GameObject*)obj)->anim.localPosY;
            vz = target[2] - ((GameObject*)obj)->anim.localPosZ;
            d = sqrtf(vx * vx + vy * vy + vz * vz);
            vx /= d;
            vy /= d;
            vz /= d;
            ((BackpackState*)aux)->unk294 = timeDelta * lbl_803E2F98 + ((BackpackState*)aux)->unk294;
            {
                f32 k = lbl_803E2FBC;
                ((GameObject*)obj)->anim.velocityX = (k * vx) * ((BackpackState*)aux)->unk294;
                ((GameObject*)obj)->anim.velocityY = (k * vy) * ((BackpackState*)aux)->unk294;
                ((GameObject*)obj)->anim.velocityZ = (k * vz) * ((BackpackState*)aux)->unk294;
            }
            d = getXZDistance(&((GameObject*)obj)->anim.localPosX, ((BackpackState*)aux)->unk290);
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            if (getXZDistance(&((GameObject*)obj)->anim.localPosX, ((BackpackState*)aux)->unk290) > d)
            {
                ((GameObject*)obj)->anim.localPosX += ((((BackpackState*)aux)->unk290)[0] - ((GameObject*)obj)->anim.
                    localPosX) * lbl_803E2F98;
                ((GameObject*)obj)->anim.localPosY += ((((BackpackState*)aux)->unk290)[1] - ((GameObject*)obj)->anim.
                    localPosY) * lbl_803E2F98;
                ((GameObject*)obj)->anim.localPosZ += ((((BackpackState*)aux)->unk290)[2] - ((GameObject*)obj)->anim.
                    localPosZ) * lbl_803E2F98;
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
            ((GameObject*)obj)->anim.localPosX = (((BackpackState*)aux)->unk290)[0];
            ((GameObject*)obj)->anim.localPosY = (((BackpackState*)aux)->unk290)[1];
            ((GameObject*)obj)->anim.localPosZ = (((BackpackState*)aux)->unk290)[2];
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

/*
 * --INFO--
 *
 * Function: tumbleweed_init
 * EN v1.0 Address: 0x80164F2C
 * EN v1.0 Size: 420b
 */
void tumbleweed_init(int obj, int defData)
{
    int aux = *(int*)&((GameObject*)obj)->extra;

    ((BackpackState*)aux)->unk288 = ((GameObject*)obj)->anim.localPosX;
    ((BackpackState*)aux)->unk28C = ((GameObject*)obj)->anim.localPosZ;
    ((BackpackState*)aux)->unk26A = (short)(lbl_803E2FCC * *(f32*)(defData + 0x1c));
    ((BackpackState*)aux)->unk279 = *(u8*)(defData + 0x1b);
    ((BackpackState*)aux)->targetScale = ((GameObject*)obj)->anim.rootMotionScale;
    ((BackpackState*)aux)->growRate = ((BackpackState*)aux)->targetScale / (f32)(s32)
    randomGetRange(0xc8, 0x1f4);
    *(u32*)&((BackpackState*)aux)->unk284 = 0;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E2FD0;
    (*gPathControlInterface)->init((void*)aux, 0, 0x40000, 1);
    (*gPathControlInterface)->setLocalPointCollision((void*)aux, 1, lbl_80320288, lbl_803DBD40, 8);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)aux);
    ((BackpackState*)aux)->phase = 0;
    ((BackpackState*)aux)->phaseTimer = lbl_803E2FB4 + (f32)(s32)
    randomGetRange(-0x12c, 0x12c);
    ObjGroup_AddObject(obj, 3);
    ObjGroup_AddObject(obj, 0x31);
    ObjHits_DisableObject(obj);
    ObjMsg_AllocQueue((void*)obj, 1);
    if (((GameObject*)obj)->anim.seqId == TUMBLEWEED_TYPE_3)
    {
        ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 0x10);
    }
}

/*
 * --INFO--
 *
 * Function: tumbleweed_updateEffects
 * EN v1.0 Address: 0x80164C44
 * EN v1.0 Size: 672b
 */
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
        state->mode = 5;
        state->despawnTimer = lbl_803E2FC8;
        ObjHits_DisableObject(obj);
        state->effectFlags = (u8)(state->effectFlags & ~TUMBLEWEED_EFFECT_FLAG_DESPAWN);
    }

    if ((state->effectFlags & TUMBLEWEED_EFFECT_FLAG_HIT_PULSE) != 0 &&
        (((GameObject*)obj)->objectFlags & 0x800) != 0)
    {
        u32 r;
        ObjHits_SetHitVolumeSlot(obj, TUMBLEWEED_HIT_PULSE_VOLUME_SLOT, 1, 0);
        r = state->hitPulseCounter;
        r = r + 1;
        state->hitPulseCounter = r;
        r = (u8)r;
        if ((int)r % TUMBLEWEED_HIT_PULSE_PERIOD != 0)
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

/*
 * --INFO--
 *
 * Function: LandedArwing_TriggerLaunchTarget
 * EN v1.0 Address: 0x801650D8
 * EN v1.0 Size: 176b
 */
int LandedArwing_TriggerLaunchTarget(int obj, int target)
{
    int* aux = ((GameObject*)obj)->extra;
    if ((s8) * (u8*)(target + 0x27a) != 0)
    {
        (*(int(**)(int, int, int, int))(*(int*)gBaddieControlInterface + 0x4c))(
            obj, (int)((LandedArwingTriggerLaunchTargetState*)aux)->unk3F0, -1, 0);
        (*(int(**)(int, int, int, int, int))(*(int*)gPlayerInterface + 0x58))(obj, target, 0x3c, 0xa, 0);
        GameBit_Set((int)((LandedArwingTriggerLaunchTargetState*)aux)->unk3F2, 1);
        ((LandedArwingTriggerLaunchTargetState*)aux)->unk405 = 0;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: LandedArwing_UpdateBounceFade
 * EN v1.0 Address: 0x80165188
 * EN v1.0 Size: 592b
 */
int LandedArwing_UpdateBounceFade(int obj, u32* stateWord)
{
    f32 horizontalDamping;
    LandedArwingState* state;
    ObjHitsPriorityState* hitState;

    state = (LandedArwingState*)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    *(u8*)((int)stateWord + 0x34d) = 3;
    if (*(s8*)((int)stateWord + 0x27a) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityX;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2FD8;
        ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityZ;
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2FDC, 0);
        state->animSpeed = lbl_803E2FE0;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairHitVolume = 0;
    *stateWord = *stateWord | 0x4000;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (horizontalDamping = lbl_803E2FE4);
    ((GameObject*)obj)->anim.velocityY = lbl_803E2FE8 * (((GameObject*)obj)->anim.velocityY - lbl_803E2FEC);
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * horizontalDamping;
    objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (((GameObject*)obj)->anim.localPosX < state->boundsMinX)
    {
        ((GameObject*)obj)->anim.localPosX = state->boundsMinX;
        ((GameObject*)obj)->anim.velocityX = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityX;
    }
    if (((GameObject*)obj)->anim.localPosX > state->boundsMaxX)
    {
        ((GameObject*)obj)->anim.localPosX = state->boundsMaxX;
        ((GameObject*)obj)->anim.velocityX = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityX;
    }
    if (((GameObject*)obj)->anim.localPosY < state->boundsMinY)
    {
        ((GameObject*)obj)->anim.localPosY = state->boundsMinY;
        ((GameObject*)obj)->anim.velocityY = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityY;
    }
    if (((GameObject*)obj)->anim.localPosY > state->boundsMaxY)
    {
        ((GameObject*)obj)->anim.localPosY = state->boundsMaxY;
        ((GameObject*)obj)->anim.velocityY = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityY;
    }
    if (((GameObject*)obj)->anim.localPosZ < state->boundsMinZ)
    {
        ((GameObject*)obj)->anim.localPosZ = state->boundsMinZ;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityZ;
    }
    if (((GameObject*)obj)->anim.localPosZ > state->boundsMaxZ)
    {
        ((GameObject*)obj)->anim.localPosZ = state->boundsMaxZ;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityZ;
    }
    if (lbl_803E2FF4 == ((GameObject*)obj)->anim.currentMoveProgress)
    {
        ObjMsg_SendToObjects(0, 3, (void*)obj, 0xe0000, obj);
        Obj_FreeObject(obj);
        return 0;
    }
    else
    {
        ((GameObject*)obj)->anim.alpha =
            (u8)(255 - (s32)(lbl_803E2FF8 * ((GameObject*)obj)->anim.currentMoveProgress));
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: LandedArwing_UpdateRetreatChase
 * EN v1.0 Address: 0x801653D8
 * EN v1.0 Size: 436b
 */
int LandedArwing_UpdateRetreatChase(int obj, int stateWord)
{
    f32 scale;
    int player;
    LandedArwingState* state;
    f32 x;
    f32 y;
    f32 z;

    state = (LandedArwingState*)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    player = (int)Obj_GetPlayerObject();
    *(u8*)(stateWord + 0x34d) = 1;
    if (*(s8*)(stateWord + 0x27a) != 0)
    {
        state->scriptTimer = 0x3c;
        state->speed = lbl_803E2FFC;
        ObjHits_DisableObject(obj);
    }
    if (state->surfaceMode == 6)
    {
        goto use_player_reflect_position;
    }
    if ((u32)player == 0)
    {
        goto use_object_position;
    }
    if (*(f32*)(player + 0x18) < state->boundsMinX)
    {
        goto use_object_position;
    }
    if (*(f32*)(player + 0x18) > state->boundsMaxX)
    {
        if (*(f32*)(player + 0x1c) < state->boundsMinY)
        {
            goto use_object_position;
        }
    }
    if (*(f32*)(player + 0x1c) > state->boundsMaxY)
    {
        if (*(f32*)(player + 0x20) < state->boundsMinZ)
        {
            goto use_object_position;
        }
    }
    if (*(f32*)(player + 0x20) > state->boundsMaxZ)
    {
        goto use_object_position;
    }
    goto use_player_reflect_position;
use_object_position:
    {
        x = ((GameObject*)obj)->anim.localPosX;
        y = ((GameObject*)obj)->anim.localPosY;
        z = ((GameObject*)obj)->anim.localPosZ;
        scale = lbl_803E2FDC;
        goto update_action;
    }
use_player_reflect_position:
    {
        x = ((GameObject*)obj)->anim.localPosX - lbl_803E3000 * (*(f32*)(player + 0xc) - ((GameObject*)obj)->anim.
            localPosX);
        y = ((GameObject*)obj)->anim.localPosY - lbl_803E3000 * (*(f32*)(player + 0x10) - ((GameObject*)obj)->anim.
            localPosY);
        z = ((GameObject*)obj)->anim.localPosZ - lbl_803E3000 * (*(f32*)(player + 0x14) - ((GameObject*)obj)->anim.
            localPosZ);
        scale = lbl_803E2FF4;
    }
update_action:
    updateConstrainedChaseVelocity(obj, x, y, z, scale);
    if (state->surfaceMode == 6)
    {
        if ((u32)((state->flags92 >> 2) & 1) != 0U)
        {
            fn_80165B3C(obj, (int)state);
        }
        else
        {
            fn_80166444(obj, (int)state);
        }
    }
    else
    {
        landedarwing_moveSurfaceCrawler(obj, (int)state);
    }
    if ((int)state->scriptTimer <= (int)(u32)framesThisStep)
    {
        return 2;
    }
    state->scriptTimer -= framesThisStep;
    return 0;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_updateTargetedStateMachine
 * EN v1.0 Address: 0x80164940
 * EN v1.0 Size: 772b
 */
void tumbleweed_updateTargetedStateMachine(int obj)
{
    int sphereIndex;
    u32 hitVolume;
    int hitObject;
    int animPhase;
    int aux;
    GameObject* player;
    u32 state;

    aux = *(int*)&((GameObject*)obj)->extra;
    state = ((BackpackState*)aux)->phase;
    if (state == 0)
    {
        if ((*(int(**)(int*))(*(int*)gSHthorntailAnimationInterface + 0x24))(&animPhase) != 0)
        {
            if (((GameObject*)obj)->anim.rootMotionScale < ((BackpackState*)aux)->targetScale)
            {
                ((GameObject*)obj)->anim.rootMotionScale = ((BackpackState*)aux)->growRate * timeDelta + ((GameObject*)
                    obj)->anim.rootMotionScale;
            }
            else
            {
                ((BackpackState*)aux)->phase = 1;
            }
        }
    }
    else if (state == 1)
    {
        if ((*(int(**)(int*))(*(int*)gSHthorntailAnimationInterface + 0x24))(&animPhase) != 0)
        {
            f32 dx, dz, d;
            player = (GameObject*)((BackpackState*)aux)->unk284;
            player = player ? player : (GameObject*)Obj_GetPlayerObject();
            dx = ((GameObject*)obj)->anim.localPosX - player->anim.localPosX;
            dz = ((GameObject*)obj)->anim.localPosZ - player->anim.localPosZ;
            d = sqrtf(dx * dx + dz * dz);
            *(s16*)&((BackpackState*)aux)->unk268 = d;
            if (((BackpackState*)aux)->unk268 < *(u16*)&((BackpackState*)aux)->unk26A)
            {
                ((BackpackState*)aux)->phase = 2;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
                ObjHits_EnableObject(obj);
            }
        }
    }
    else if (state == 2)
    {
        f32 dz, dx, d;
        u32 dist;
        player = (GameObject*)((BackpackState*)aux)->unk284;
        player = player ? player : (GameObject*)Obj_GetPlayerObject();
        dx = ((GameObject*)obj)->anim.localPosX - player->anim.localPosX;
        dz = ((GameObject*)obj)->anim.localPosZ - player->anim.localPosZ;
        d = sqrtf(dx * dx + dz * dz);
        *(s16*)&((BackpackState*)aux)->unk268 = d;
        dist = ((BackpackState*)aux)->unk268;
        if ((f32)dist > lbl_803E2FC4)
        {
            f32 k;
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - dx / (lbl_803E2FC4 * (f32)dist);
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - dz / (lbl_803E2FC4 * (f32)(u32)(
                (BackpackState*)aux)->unk268);
            k = lbl_803E2FAC;
            ((BackpackState*)aux)->unk27C = k * ((GameObject*)obj)->anim.velocityX;
            ((BackpackState*)aux)->unk27E = k * ((GameObject*)obj)->anim.velocityZ;
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
            ((BackpackState*)aux)->unk27A = (u8)(((BackpackState*)aux)->unk27A | 7);
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
