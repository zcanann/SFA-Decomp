/* === merged from main/dll/waterfallControl.c [80163BBC-801641B0) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/waterfallControl.h"


extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int* hitsOut, int pointCount,
                                int mask);

extern f32 timeDelta;
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F60;
extern f32 lbl_803E2F64;
extern f32 lbl_803E2F68;
extern f64 lbl_803E2F70;
extern f32 lbl_803E2F78;
extern f32 lbl_803E2F7C;
extern f32 lbl_803E2F80;
extern f32 lbl_803E2F84;
extern f32 lbl_803E2F88;
extern f64 lbl_803E2F90;
extern f32 lbl_803E2F98;
extern f32 lbl_803E2F9C;


/*
 * --INFO--
 *
 * Function: tumbleweed_updateRollingMotion
 * EN v1.0 Address: 0x80163BBC
 * EN v1.0 Size: 976b
 */
#pragma scheduling off
void tumbleweed_updateRollingMotion(short* obj, int state)
{
    extern u32 randomGetRange(int min, int max); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    int hitCount;
    uint uval;
    undefined4* hitEntry;
    int i;
    int bestHit;
    f32 dy;
    f32 bestDy;
    undefined4* hitList[2];

    hitList[0] = (undefined4*)0x0;
    bestDy = lbl_803E2F78;
    hitCount = hitDetectFn_80065e50(*(float*)(obj + 6), *(float*)(obj + 8),
                                 *(float*)(obj + 10), (int)obj, (int*)hitList, 0, 0);
    bestHit = 0;
    hitEntry = hitList[0];
    for (i = 0; i < hitCount; i++)
    {
        dy = *(float*)(obj + 8) - *(float*)*hitEntry;
        if (dy < lbl_803E2F68)
        {
            dy = lbl_803E2F7C * dy + lbl_803E2F5C;
        }
        if (dy < bestDy)
        {
            bestHit = i;
            bestDy = dy;
        }
        hitEntry = hitEntry + 1;
    }
    if (*(float*)(obj + 0x12) > lbl_803E2F80)
    {
        *(float*)(obj + 0x12) = lbl_803E2F80;
    }
    else if (*(float*)(obj + 0x12) < lbl_803E2F7C)
    {
        *(float*)(obj + 0x12) = lbl_803E2F7C;
    }
    if (*(float*)(obj + 0x14) > lbl_803E2F80)
    {
        *(float*)(obj + 0x14) = lbl_803E2F80;
    }
    else if (*(float*)(obj + 0x14) < lbl_803E2F7C)
    {
        *(float*)(obj + 0x14) = lbl_803E2F7C;
    }
    if (*(float*)(obj + 0x16) > lbl_803E2F80)
    {
        *(float*)(obj + 0x16) = lbl_803E2F80;
    }
    else if (*(float*)(obj + 0x16) < lbl_803E2F7C)
    {
        *(float*)(obj + 0x16) = lbl_803E2F7C;
    }
    *(float*)(obj + 6) = *(float*)(obj + 0x12) * timeDelta + *(float*)(obj + 6);
    *(float*)(obj + 8) = *(float*)(obj + 0x14) * timeDelta + *(float*)(obj + 8);
    *(float*)(obj + 10) = *(float*)(obj + 0x16) * timeDelta + *(float*)(obj + 10);
    hitCount = (int)((f32)(int) * (s16*)(state + 0x27c) * timeDelta + (f32)(int)
    obj[2]
    )
    ;
    obj[2] = (short)hitCount;
    hitCount = (int)((f32)(int) * (s16*)(state + 0x27e) * timeDelta + (f32)(int)
    obj[1]
    )
    ;
    obj[1] = (short)hitCount;
    hitCount = (int)((f32)(int) * (s16*)(state + 0x280) * timeDelta + (f32)(int) * obj);
    *obj = (short)hitCount;
    if (hitList[0] != (undefined4*)0x0)
    {
        if (lbl_803E2F60 + *(float*)hitList[0][bestHit] < *(float*)(obj + 8))
        {
            *(float*)(obj + 0x14) = *(float*)(obj + 0x14) + lbl_803E2F64;
        }
        else
        {
            *(float*)(obj + 8) = lbl_803E2F60 + *(float*)hitList[0][bestHit];
            if (obj[0x23] == 0x3fb)
            {
                uval = randomGetRange(0x8c, 0xb4);
                *(f32*)(obj + 0x14) =
                    -(lbl_803E2F84 * *(f32*)(obj + 0x14) *
                        ((f32) * (ushort*)(state + 0x268) / (f32)(int)
                uval
                )
                )
                ;
            }
            else
            {
                uval = randomGetRange(0x14, 0x28);
                *(f32*)(obj + 0x14) =
                    -(lbl_803E2F84 * *(f32*)(obj + 0x14) *
                        ((f32) * (ushort*)(state + 0x268) / (f32)(int)
                uval
                )
                )
                ;
            }
            bestHit = (int)(lbl_803E2F88 * *(f32*)(obj + 0x14));
            if (0x7f < bestHit)
            {
                bestHit = 0x7f;
            }
            if (0x10 < bestHit)
            {
                Sfx_PlayFromObject((int)obj, SFXsc_gethit02);
                uval = randomGetRange(0, 5);
                if ((uval == 0) && ((*(byte*)(state + 0x27a) & 8) != 0))
                {
                    Sfx_PlayFromObject((int)obj, SFXsc_gethit03);
                }
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0F
 * EN v1.0 Address: 0x80163F8C
 * EN v1.0 Size: 12b
 */
#pragma peephole off
void tumbleweed_func0F(int obj, int value)
{
    *(int*)(*(int*)&((GameObject*)obj)->extra + 0x284) = value;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0E
 * EN v1.0 Address: 0x80163F98
 * EN v1.0 Size: 24b
 */
int tumbleweed_func0E(int obj)
{
    return *(byte*)(*(int*)&((GameObject*)obj)->extra + 0x278) == 6;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_render2
 * EN v1.0 Address: 0x80163FB0
 * EN v1.0 Size: 64b
 */
void tumbleweed_render2(int* obj, int p2)
{
    extern void ObjHits_DisableObject(int obj); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    *(u8*)((char*)state + 0x278) = 6;
    *(int*)((char*)state + 0x290) = p2;
    *(f32*)((char*)state + 0x294) = timeDelta * lbl_803E2F98;
    ObjHits_DisableObject((int)obj);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_modelMtxFn
 * EN v1.0 Address: 0x80163FF0
 * EN v1.0 Size: 112b
 */
void tumbleweed_modelMtxFn(int obj)
{
    extern void ObjHits_EnableObject(int obj); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    if (*(u8*)(state + 0x278) == 1)
    {
        ObjHits_EnableObject(obj);
        *(u8*)(state + 0x278) = 2;
        *(u8*)(state + 0x27a) |= 3;
        if (((GameObject*)obj)->anim.seqId == 0x4c1)
        {
            *(f32*)(state + 0x2a0) = lbl_803E2F9C;
        }
    }
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0B
 * EN v1.0 Address: 0x80164060
 * EN v1.0 Size: 16b
 */
void tumbleweed_func0B(int obj, float x, float y)
{
    int extra = *(int*)&((GameObject*)obj)->extra;

    *(float*)(extra + 0x288) = x;
    *(float*)(extra + 0x28c) = y;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_setScale
 * EN v1.0 Address: 0x80164070
 * EN v1.0 Size: 12b
 */
int tumbleweed_setScale(int obj)
{
    return *(byte*)(*(int*)&((GameObject*)obj)->extra + 0x278);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_getExtraSize
 * EN v1.0 Address: 0x8016407C
 * EN v1.0 Size: 8b
 */
int tumbleweed_getExtraSize(void)
{
    return 0x2a4;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_free
 * EN v1.0 Address: 0x80164084
 * EN v1.0 Size: 252b
 */
void tumbleweed_free(int* obj)
{
    extern int* ObjList_GetObjects(int* startIndex, int* objectCount); /* #57 */
    extern void ObjGroup_RemoveObject(int* obj, int group); /* #57 */
    int* items;
    int counter;
    int limit;
    int target_id;

    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x39d:
        target_id = 0x28d;
        break;
    case 0x3fb:
        target_id = 0x3fd;
        break;
    case 0x4ba:
        target_id = 0x4b9;
        break;
    case 0x4c1:
        target_id = 0x4be;
        break;
    }

    items = ObjList_GetObjects(&counter, &limit);
    while (counter < limit)
    {
        int* o = (int*)items[counter];
        if (target_id == *(s16*)((int)o + 0x46))
        {
            (*(code*)(**(int**)((int)o + 0x68) + 0x20))(o, obj);
        }
        counter = counter + 1;
    }
    ObjGroup_RemoveObject(obj, 3);
    ObjGroup_RemoveObject(obj, 0x31);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_render
 * EN v1.0 Address: 0x80164180
 * EN v1.0 Size: 48b
 */
void tumbleweed_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32); /* #57 */
    if ((s32)visible >= 1) objRenderFn_8003b8f4(lbl_803E2F80);
}
#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma peephole reset

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
int LandedArwing_ReturnZero(void);

/*
 * --INFO--
 *
 * Function: tumbleweed_updateStateMachine
 * EN v1.0 Address: 0x801641B0
 * EN v1.0 Size: 1936b
 */
void tumbleweed_updateStateMachine(int obj)
{
    extern void tumbleweed_updateRollingMotion(int obj, int aux); /* #57 */
    extern void ObjHits_EnableObject(int obj); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId);
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
    extern void ObjHits_DisableObject(int obj); /* #57 */
    extern u32 randomGetRange(int min, int max); /* #57 */
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
    extern void ObjHits_DisableObject(int obj); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
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
int LandedArwing_TriggerLaunchTarget(int obj, int target);

/*
 * --INFO--
 *
 * Function: LandedArwing_UpdateBounceFade
 * EN v1.0 Address: 0x80165188
 * EN v1.0 Size: 592b
 */
int LandedArwing_UpdateBounceFade(int obj, u32* stateWord);

/*
 * --INFO--
 *
 * Function: LandedArwing_UpdateRetreatChase
 * EN v1.0 Address: 0x801653D8
 * EN v1.0 Size: 436b
 */
int LandedArwing_UpdateRetreatChase(int obj, int stateWord);

/*
 * --INFO--
 *
 * Function: tumbleweed_updateTargetedStateMachine
 * EN v1.0 Address: 0x80164940
 * EN v1.0 Size: 772b
 */
void tumbleweed_updateTargetedStateMachine(int obj)
{
    extern void tumbleweed_updateRollingMotion(int obj, int aux); /* #57 */
    extern void ObjHits_EnableObject(int obj); /* #57 */
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
