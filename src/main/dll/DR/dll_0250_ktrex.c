#include "main/dll/partfx_interface.h"
#include "main/dll/objfsa_romcurve.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/audio/music_api.h"
#include "main/audio/stream_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/camera.h"
#include "main/pad.h"
#include "main/vecmath.h"
#include "main/map_load.h"
#include "main/objprint_api.h"
#include "main/objprint_character_api.h"
#include "main/dll/DR/dr_shared.h"
#include "main/dll/DR/dll_0250_ktrex.h"
#include "main/newclouds.h"
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/modellight_api.h"
#include "main/object_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/dll/DR/dll_0251_ktrexfloorswitch.h"
#include "main/dll/DR/dll_0252_ktlazerwall.h"
#include "main/dll/DR/dll_0253_ktlazerlight.h"
#include "main/dll/DR/dll_0254_ktfallingrocks.h"
#include "main/dll/DR/dll_0261_drlasercannon.h"
#include "main/dll/dll_0263_gmmazewell.h"
#include "main/player_control_interface.h"

#define CAMMODE_DEFAULT 0x42 /* dll_0042 - default/release camera */

#define KTREX_OBJGROUP         0x3
#define KTREX_ADVANCE_MSG      0xe0001 /* notify the struck object to advance its hit reaction */
#define KTREX_PARTFX_HIT       0x328   /* hit-response effect spawned at the player contact point */
#define MODEL_LIGHT_KIND_POINT 2

extern void drakormissile_abortStraightFlight(GameObject*);
extern void drakormissile_modelMtxFn(GameObject*);
extern void drakormissile_startStraightLaunch(GameObject*);
extern void drakormissile_setScale(GameObject*);
extern void drakormissile_getExtraSize(void);
extern void drakormissile_getObjectTypeId(void);
extern void drakormissile_free(GameObject*);
extern void drakormissile_render(GameObject*);
extern void drakormissile_hitDetect(void);
extern void drakormissile_update(void);
extern void drakormissile_init(GameObject*);
extern void drakormissile_release(void);
extern void drakormissile_initialise(void);

__declspec(section ".rodata") KtrexMsgBlob gKTRexMsgTemplate = {{6, 0x69, 0x69, 0xFF}};

static inline f32* KTRex_GetActiveContactPointTable(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    u8* model = (u8*)objAnim->banks[objAnim->bankIndex];
    return *(f32**)(model + 0x50);
}

int ktrex_stateHandlerA00(void)
{
    return 0x0;
}

void ktrex_func0B(void)
{
}

int ktrex_getExtraSize(void)
{
    return 0x5a4;
}

int ktrex_getObjectTypeId(void)
{
    return 0x49;
}

void ktrex_release(void)
{
}

int ktrex_animEventCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            *(int*)&gKTRexState->phaseFlags |= 4;
            break;
        case 2:
            *(int*)&gKTRexState->phaseFlags |= 8;
            break;
        case 3:
            *(int*)&gKTRexState->phaseFlags |= 0x800;
            break;
        case 4:
            *(int*)&gKTRexState->phaseFlags |= 0x1000;
            break;
        case 5:
            *(u32*)&gKTRexState->phaseFlags |= 0x20000LL;
            break;
        case 6:
            if (gKTRexState->light != NULL)
            {
                ModelLightStruct_free(gKTRexState->light);
                gKTRexState->light = NULL;
            }
            break;
        }
    }
    ktrex_updateAttackEffects(obj);
    if ((obj)->unkF8 == 0)
    {
        (obj)->unkF8 = 1;
    }
    else if ((obj)->unkF8 == 3)
    {
        (obj)->unkF8 = 4;
    }
    return 0;
}

#pragma dont_inline on
void ktrex_spawnRandomEnergyArc(int obj, int angle, f32 arcLen, int slot)
{
    int* model;
    f32 point1[3];
    f32 point2[3];
    f32 localPoint[3];

    if (((void**)((char*)gKTRexState + 0x17c))[slot] != NULL)
    {
        mm_free(((void**)((char*)gKTRexState + 0x17c))[slot]);
        ((void**)((char*)gKTRexState + 0x17c))[slot] = NULL;
    }
    model = (int*)Obj_GetActiveModel((GameObject*)obj);
    localPoint[0] = lbl_803E67B8;
    localPoint[1] = lbl_803E67B8;
    localPoint[2] = lbl_803E67B8;

    PSMTXMultVec((f32*)ObjModel_GetJointMatrix((u8*)model, randomGetRange(0, *(u8*)(*(int*)model + 0xf3) - 1)), localPoint,
                 point1);
    point1[0] = point1[0] + playerMapOffsetX;
    point1[1] = point1[1] + lbl_803E67BC;
    point1[2] = point1[2] + playerMapOffsetZ;

    PSMTXMultVec((f32*)ObjModel_GetJointMatrix((u8*)model, randomGetRange(0, *(u8*)(*(int*)model + 0xf3) - 1)), localPoint,
                 point2);
    point2[0] = point2[0] + playerMapOffsetX;
    point2[2] = point2[2] + playerMapOffsetZ;

    ((void**)((char*)gKTRexState + 0x17c))[slot] =
        lightningCreateU16Promoted((const Vec3f*)point1, (const Vec3f*)point2, lbl_803E67B4, lbl_803E67C0, angle, 96,
                                   0);
}
#pragma dont_inline reset

int ktrex_stateHandlerA06(GameObject* obj, KTRexRuntime* runtime)
{
    int slot;
    if (*(s8*)&runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 5);
    }
    else if (*(s8*)&runtime->moveDone != 0)
    {
        slot = 0;
        if (Stack_IsEmpty(gKTRexState->stack) == 0)
        {
            Stack_Pop(gKTRexState->stack, &slot);
        }
        return slot + 1;
    }
    return 0;
}

#pragma dont_inline on
int ktrex_isPlayerInLaneThreatRange(GameObject* obj)
{
    u8 state = gKTRexState->laneMode;
    f32 center;
    f32 lo;
    f32 hi;
    if (state == 0)
    {
        return 0;
    }
    switch (state)
    {
    case 1:
    case 2:
        center = obj->anim.localPosZ;
        lo = (center - gKTRexLaneThreatHalfWidth) - gKTRexMapBlock->worldZ;
        hi = (gKTRexLaneThreatHalfWidth + center) - gKTRexMapBlock->worldZ;
        if (lo > lbl_803E6840 || hi < lbl_803E6840)
        {
            return 0;
        }
        return 1;
    case 4:
    case 8:
        center = obj->anim.localPosX;
        lo = (center - gKTRexLaneThreatHalfWidth) - gKTRexMapBlock->worldX;
        hi = (gKTRexLaneThreatHalfWidth + center) - gKTRexMapBlock->worldX;
        if (lo > lbl_803E6844 || hi < lbl_803E6844)
        {
            return 0;
        }
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

int ktrex_setScale(GameObject* obj)
{
    void* p = obj->extra;
    gKTRexRuntime = p;
    return ((KtrexState*)p)->scale;
}

void ktrex_initialise(void)
{
    ktrex_initialiseStateHandlerTables();
}

int ktrex_stateHandlerB00(GameObject* obj, KTRexRuntime* runtime)
{
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E67B8, 0);
    }
    runtime->curvePhase = lbl_803E6808;
    return 0;
}

void ktrex_hitDetect(GameObject* obj)
{
    f32 z, y, x;
    if (gKTRexState->light != 0)
    {
        ObjPath_GetPointWorldPosition(obj, 5, &x, &y, &z, 0);
        modelLightStruct_setPosition(gKTRexState->light, x, y, z);
        modelLightStruct_updateGlowAlpha(gKTRexState->light);
    }
}

void ktrex_free(GameObject* obj)
{
    int i;
    gKTRexRuntime = obj->extra;
    ObjGroup_RemoveObject((int)obj, KTREX_OBJGROUP);
    (*(void (**)(void*, void*, int))((char*)*gBaddieControlInterface + 0x40))(obj, gKTRexRuntime, 0);
    Stack_Free(*(void**)gKTRexState);
    if (gKTRexResource != NULL)
    {
        Resource_Release(gKTRexResource);
    }
    if (gKTRexState->light != 0)
    {
        ModelLightStruct_free(gKTRexState->light);
    }
    for (i = 0; i < KTREX_LIGHTNING_COUNT; i++)
    {
        void* m = gKTRexState->lightning[i];
        if (m != 0)
        {
            mm_free(m);
        }
    }
    gKTRexResource = NULL;
    Music_Trigger(MUSICTRIG_mammoth_walk, 0);
    Music_Trigger(MUSICTRIG_menu_page, 0);
    Music_Trigger(MUSICTRIG_guard_theme, 0);
}

int ktrex_shouldAdvanceArenaPhase(void)
{
    u8 currentMask;
    u8 activeMask;
    KTRexArenaState* s = (KTRexArenaState*)gKTRexState;
    int r6;
    r6 = s->timerFA & 1;
    currentMask = s->currentLaneMask;
    activeMask = s->activeLaneMask;
    if ((currentMask & gKTRexState->activeLaneMask) != 0)
    {
        if (r6 != 0)
        {
            if (gKTRexState->laneLerpT < gKTRexState->laneFrac)
            {
                return 1;
            }
        }
        else
        {
            if (gKTRexState->laneLerpT > gKTRexState->laneFrac)
            {
                return 1;
            }
        }
        return 0;
    }
    if (r6 != 0)
    {
        if ((currentMask == 8 && (gKTRexState->activeLaneMask & 1)) ||
            (currentMask == 2 && (gKTRexState->activeLaneMask & 8)) ||
            (currentMask == 4 && (gKTRexState->activeLaneMask & 2)) ||
            (currentMask == 1 && (gKTRexState->activeLaneMask & 4)))
        {
            return 1;
        }
        return 0;
    }
    if ((currentMask == 1 && (gKTRexState->activeLaneMask & 8)) ||
        (currentMask == 4 && (activeMask & 1)) || (currentMask == 2 && (activeMask & 4)) ||
        (currentMask == 8 && (activeMask & 2)))
    {
        return 1;
    }
    return 0;
}

void ktrex_initialiseStateHandlerTables(void)
{
    gKTRexStateHandlersB[0] = ktrex_stateHandlerB00;
    gKTRexStateHandlersB[1] = ktrex_stateHandlerB01;
    gKTRexStateHandlersB[2] = ktrex_stateHandlerB02;
    gKTRexStateHandlersB[3] = ktrex_stateHandlerB03;
    gKTRexStateHandlersB[4] = ktrex_stateHandlerB04;
    gKTRexStateHandlersB[5] = ktrex_stateHandlerB05;
    gKTRexStateHandlersB[6] = ktrex_stateHandlerB06;
    gKTRexStateHandlersB[7] = ktrex_stateHandlerB07;
    gKTRexStateHandlersB[8] = ktrex_stateHandlerB08;
    gKTRexStateHandlersA[0] = ktrex_stateHandlerA00;
    gKTRexStateHandlersA[1] = ktrex_stateHandlerA01;
    gKTRexStateHandlersA[2] = ktrex_stateHandlerA02;
    gKTRexStateHandlersA[3] = ktrex_stateHandlerA03;
    gKTRexStateHandlersA[4] = ktrex_stateHandlerA04;
    gKTRexStateHandlersA[5] = ktrex_stateHandlerA05;
    gKTRexStateHandlersA[6] = ktrex_stateHandlerA06;
    gKTRexStateHandlersA[7] = ktrex_stateHandlerA07;
    gKTRexStateHandlersA[8] = ktrex_stateHandlerA08;
    gKTRexStateHandlersA[9] = ktrex_stateHandlerA09;
    gKTRexStateHandlersA[10] = ktrex_stateHandlerA10;
    gKTRexStateHandlersA[11] = ktrex_stateHandlerA11;
}

int ktrex_updateArenaPathProgress(KTRexRuntime* runtime)
{
    u16 flags;
    int phase;
    int dir;
    f32 speed;
    int changed;

    changed = 0;
    flags = gKTRexState->timerFA;
    dir = flags & 1;
    phase = (flags >> 1) & 3;
    if (dir != 0)
    {
        speed = -runtime->laneSpeed;
    }
    else
    {
        speed = runtime->laneSpeed;
    }
    gKTRexState->laneLerpT = speed * timeDelta + gKTRexState->laneLerpT;
    if ((gKTRexState->laneLerpT > gKTRexLaneSpeedMax[gKTRexState->laneIndex] &&
         speed > lbl_803E67B8) ||
        (gKTRexState->laneLerpT < gKTRexLaneSpeedMin[gKTRexState->laneIndex] &&
         speed < lbl_803E67B8))
    {
        if (dir != 0)
        {
            phase--;
            if (phase < 0)
            {
                phase = 3;
            }
        }
        else
        {
            phase++;
            if (phase >= 4)
            {
                phase = 0;
            }
        }
        gKTRexState->timerFA = gKTRexState->timerFA & ~6;
        gKTRexState->timerFA = gKTRexState->timerFA | (phase << 1);
        if (gKTRexState->laneLerpT > gKTRexLaneSpeedMax[gKTRexState->laneIndex])
        {
            gKTRexState->laneLerpT = gKTRexLaneSpeedMax[gKTRexState->laneIndex];
        }
        else if (gKTRexState->laneLerpT <
                 gKTRexLaneSpeedMin[gKTRexState->laneIndex])
        {
            gKTRexState->laneLerpT = gKTRexLaneSpeedMin[gKTRexState->laneIndex];
        }
        changed = 1;
    }
    gKTRexState->posX =
        gKTRexState->laneLerpT * (((f32*)*(int*)&gKTRexState->rowBX)[phase] -
                                                      ((f32*)*(int*)&gKTRexState->rowAX)[phase]) +
        ((f32*)*(int*)&gKTRexState->rowAX)[phase];
    gKTRexState->posY =
        gKTRexState->laneLerpT * (((f32*)*(int*)&gKTRexState->rowBY)[phase] -
                                                      ((f32*)*(int*)&gKTRexState->rowAY)[phase]) +
        ((f32*)*(int*)&gKTRexState->rowAY)[phase];
    gKTRexState->posZ =
        gKTRexState->laneLerpT * (((f32*)*(int*)&gKTRexState->rowBZ)[phase] -
                                                      ((f32*)*(int*)&gKTRexState->rowAZ)[phase]) +
        ((f32*)*(int*)&gKTRexState->rowAZ)[phase];
    return changed;
}

void ktrex_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    f32 m[12];
    void* e;
    int i;

    gKTRexRuntime = (obj)->extra;
    if (visible == 0)
    {
        return;
    }
    switch ((obj)->unkF4)
    {
    case 0:
        break;
    default:
        return;
    }
    if (gKTRexState->light != NULL)
    {
        queueGlowRender(gKTRexState->light);
    }
    for (i = 0; i < KTREX_LIGHTNING_COUNT; i++)
    {
        e = gKTRexState->lightning[i];
        if (e != NULL)
        {
            lightningRender((LightningEffect*)e);
            *(u16*)((char*)gKTRexState->lightning[i] + 0x20) =
                (f32)(u32) * (u16*)((char*)gKTRexState->lightning[i] + 0x20) + timeDelta;
            if (*(u16*)((char*)gKTRexState->lightning[i] + 0x20) >=
                *(u16*)((char*)gKTRexState->lightning[i] + 0x22))
            {
                mm_free(gKTRexState->lightning[i]);
                *(int*)&gKTRexState->lightning[i] = 0;
            }
        }
    }
    if (gKTRexRuntime->bobPhase != lbl_803E67B8)
    {
        fn_8003B5E0IntAlphaLegacy(200, 0, 0, (int)gKTRexRuntime->bobPhase);
    }
    objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, (double)lbl_803E6818);
    ObjPath_GetPointWorldPosition(obj, 1, (f32*)((char*)gKTRexState + 0x130), (f32*)((char*)gKTRexState + 0x134),
                                  (f32*)((char*)gKTRexState + 0x138), 0);
    ObjPath_GetPointWorldPosition(obj, 2, (f32*)((char*)gKTRexState + 0x148), (f32*)((char*)gKTRexState + 0x14c),
                                  (f32*)((char*)gKTRexState + 0x150), 0);
    ObjPath_GetPointWorldPosition(obj, 3, (f32*)((char*)gKTRexState + 0x160), (f32*)((char*)gKTRexState + 0x164),
                                  (f32*)((char*)gKTRexState + 0x168), 0);
    ObjPath_GetPointWorldPosition(obj, 0, (f32*)((char*)gKTRexState + 0x118), (f32*)((char*)gKTRexState + 0x11c),
                                  (f32*)((char*)gKTRexState + 0x120), 0);
    memcpy(m, (void*)ObjPath_GetPointModelMtx(obj, 4), 48);
    gKTRexState->vecX = lbl_803E67B4 * (f32)(int)randomGetRange(-50, 50);
    gKTRexState->vecY = lbl_803E67B4 * (f32)(int)randomGetRange(60, 120);
    gKTRexState->vecZ = lbl_803E6848 * (f32)(int)randomGetRange(100, 150);
    PSMTXMultVecSR(m, &gKTRexState->vecX, &gKTRexState->vecX);
    *(u32*)&gKTRexState->phaseFlags |= 0x100000LL;
}

void ktrex_update(int obj)
{
    KTRexRuntime* runtime;
    void* player;
    f32 d[3];
    f32* dp;
    u32 tmp;
    int zc[1];
    u8 zm[1];
    s16* bitA;
    s16* bitB;
    int flags;
    int mm;
    int phase;
    f32 dx, dz, frac;

    if (((GameObject*)obj)->unkF4 != 0)
    {
        return;
    }
    gKTRexRuntime = ((GameObject*)obj)->extra;
    runtime = gKTRexRuntime;
    if (((GameObject*)obj)->unkF8 == 1)
    {
        Music_Trigger(MUSICTRIG_mammoth_walk, 1);
        ((GameObject*)obj)->unkF8 = 2;
        runtime->unk270 = 11;
        runtime->moveJustStartedB = 1;
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    runtime->playerObj = Obj_GetPlayerObject();
    if (runtime->playerObj != NULL)
    {
        player = runtime->playerObj;
        dp = d;
        for (zc[0] = 0; zc[0] < 3; zc[0]++)
        {
            dp[zc[0]] = (&((GameObject*)player)->anim.worldPosX)[zc[0]] - (&((GameObject*)obj)->anim.worldPosX)[zc[0]];
        }
        runtime->playerDist = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
    characterDoEyeAnimsState((GameObject*)obj, (char*)gKTRexRuntime + 0x3ac);
    zm[0] = 0;
    zc[0] = zm[0];
    bitA = lbl_803DC290;
    for (; zc[0] < 4; zc[0]++)
    {
        if (mainGetBit(*bitA) != 0)
        {
            zm[0] |= 1 << zc[0];
        }
        bitA++;
    }
    gKTRexState->activeLaneMask = zm[0];
    player = runtime->playerObj;
    {
        KTRexArenaState* st = (KTRexArenaState*)gKTRexState;
        phase = (st->timerFA >> 1) & 3;
        dz = ((f32*)*(int*)&st->rowBX)[phase] - ((f32*)*(int*)&st->rowAX)[phase];
        dx = ((f32*)*(int*)&st->rowBZ)[phase] - ((f32*)*(int*)&st->rowAZ)[phase];
        if (__fabs(dz) > __fabs(dx))
        {
            frac = (((GameObject*)player)->anim.localPosX - ((f32*)*(int*)&st->rowAX)[phase]) / dz;
        }
        else
        {
            frac = (((GameObject*)player)->anim.localPosZ - ((f32*)*(int*)&st->rowAZ)[phase]) / dx;
        }
    }
    gKTRexState->laneFrac = frac;
    {
        KTRexArenaState* st = (KTRexArenaState*)gKTRexState;
        int t = st->timerFA;
        tmp = lbl_803E67B0;
        st->currentLaneMask = ((u8*)&tmp)[(t >> 1) & 3];
    }
    zm[0] = 0;
    zc[0] = zm[0];
    bitB = lbl_803DC298;
    flags = gKTRexState->currentLaneMask;
    for (; zc[0] < 4; zc[0]++)
    {
        mm = 1 << zc[0];
        if ((flags & mm) != 0 && mainGetBit(*bitB) != 0)
        {
            zm[0] |= mm;
        }
        bitB++;
    }
    gKTRexState->laneMode = zm[0];
    (*(void (**)(int, void*, void*, int, void*, int, int, int))((char*)*gBaddieControlInterface + 0x54))(
        obj, runtime, (char*)gKTRexRuntime + 0x35c, gKTRexRuntime->unk3F4,
        (char*)gKTRexRuntime + 0x405, 2, 2, 0);
    ktrex_updateContactEffects((GameObject*)obj, runtime);
    ktrex_updateAttackEffects((GameObject*)(obj));
    (*(void (**)(int, void*, f32, int))((char*)*gBaddieControlInterface + 0x2c))(obj, runtime, lbl_803E67B8, 0);
    ObjHits_SetHitVolumeMasks((ObjAnimComponent*)obj, 24, 2, 0x1fffff);
    (*(void (**)(int, void*, f32, f32, void**, void*))((char*)*gPlayerInterface + 0x8))(
        obj, runtime, timeDelta, timeDelta, gKTRexStateHandlersB, gKTRexStateHandlersA);
    ((GameObject*)obj)->anim.localPosY = gKTRexState->posY;
}
int ktrex_stateHandlerB05(GameObject* obj, KTRexRuntime* runtime)
{
    f32 z;
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, (&lbl_803DC250)[gKTRexState->laneIndex], lbl_803E67B8, 0);
        runtime->curvePhase = lbl_803E6810;
        z = lbl_803E67B8;
        runtime->localOffsetZ = z;
        runtime->localOffsetX = z;
    }
    if ((gKTRexRuntime->handlerState & 1) != 0)
    {
        gKTRexRuntime->handlerState &= ~1;
        *(int*)&gKTRexState->phaseFlags |= 0x200;
    }
    return 0;
}

int ktrex_stateHandlerB07(GameObject* obj, KTRexRuntime* runtime)
{
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 12, lbl_803E67B8, 0);
        runtime->curvePhase = lbl_803E6808;
    }
    if ((gKTRexRuntime->handlerState & 1) != 0)
    {
        gKTRexRuntime->handlerState &= ~1;
        *(int*)&gKTRexState->phaseFlags |= 0x2000;
    }
    if ((gKTRexRuntime->handlerState & 0x80) != 0)
    {
        gKTRexRuntime->handlerState &= ~0x80;
        *(u32*)&gKTRexState->phaseFlags |= 0x40000LL;
    }
    return 0;
}

int ktrex_stateHandlerB08(GameObject* obj, KTRexRuntime* runtime)
{
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 13, lbl_803E67B8, 0);
        runtime->curvePhase =
            lbl_803E67F4 + lbl_803E67F8 * (f32)(int)(gKTRexState->phaseCounter >> 1);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_rexroarlng11);
    }
    if ((gKTRexRuntime->handlerState & 1) != 0)
    {
        gKTRexRuntime->handlerState &= ~1;
        *(int*)&gKTRexState->phaseFlags |= 0x2000;
    }
    return 0;
}

int ktrex_stateHandlerB06(GameObject* obj, KTRexRuntime* runtime)
{
    f32 z;
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 11, lbl_803E67B8, 0);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_rexelctro11);
        runtime->curvePhase = lbl_803E680C;
        z = lbl_803E67B8;
        runtime->localOffsetZ = z;
        runtime->localOffsetX = z;
    }
    if ((gKTRexRuntime->handlerState & 1) != 0)
    {
        gKTRexRuntime->handlerState &= ~1;
        *(u32*)&gKTRexState->phaseFlags |= 0x80000LL;
    }
    if ((gKTRexRuntime->handlerState & 0x80) != 0)
    {
        gKTRexRuntime->handlerState &= ~0x80;
        *(u32*)&gKTRexState->phaseFlags |= 0x20000LL;
    }
    return 0;
}

int ktrex_stateHandlerB03(GameObject* obj, KTRexRuntime* runtime)
{
    f32 z;
    u16 dir;
    dir = gKTRexState->timerFA & 1;
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 15, lbl_803E67B8, 0);
        runtime->curvePhase = lbl_803E6810;
        z = lbl_803E67B8;
        runtime->localOffsetZ = z;
        runtime->localOffsetX = z;
        gKTRexState->homeYaw = (obj)->anim.rotX;
    }
    if (dir != 0)
    {
        (obj)->anim.rotX =
            lbl_803E6814 * (obj)->anim.currentMoveProgress + (f32)(int)gKTRexState->homeYaw;
    }
    else
    {
        (obj)->anim.rotX =
            (f32)(int)gKTRexState->homeYaw - lbl_803E6814 * (obj)->anim.currentMoveProgress;
    }
    return 0;
}

int ktrex_stateHandlerB04(GameObject* obj, KTRexRuntime* runtime)
{
    f32 z;
    u16 mask;
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, (&lbl_803DC260)[gKTRexState->moveVariant], lbl_803E67B8, 0);
        runtime->curvePhase = lbl_8032A51C[gKTRexState->moveVariant];
        z = lbl_803E67B8;
        runtime->localOffsetZ = z;
        runtime->localOffsetX = z;
    }
    mask = (&lbl_803DC288)[gKTRexState->moveVariant];
    if ((gKTRexRuntime->handlerState & 1) != 0)
    {
        gKTRexRuntime->handlerState &= ~1;
        *(int*)&gKTRexState->phaseFlags |= mask;
    }
    if ((gKTRexRuntime->handlerState & 0x200) != 0)
    {
        gKTRexRuntime->handlerState &= ~0x200;
        *(int*)&gKTRexState->phaseFlags |= 0x800;
    }
    if ((gKTRexRuntime->handlerState & 0x400) != 0)
    {
        gKTRexRuntime->handlerState &= ~0x400;
        *(int*)&gKTRexState->phaseFlags |= 0x1000;
    }
    return 0;
}

int ktrex_stateHandlerB01(GameObject* obj, KTRexRuntime* runtime)
{
    f32 z;
    u16 mask;
    int maskI;
    f32 dx;
    f32 dz;
    if ((s8)runtime->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, (&lbl_803DC258)[gKTRexState->laneIndex], lbl_803E67B8, 0);
        z = lbl_803E67B8;
        runtime->localOffsetZ = z;
        runtime->localOffsetX = z;
    }
    mask = (&lbl_803DC268)[gKTRexState->laneIndex];
    if ((gKTRexRuntime->handlerState & 4) != 0)
    {
        gKTRexRuntime->handlerState &= ~4;
        *(int*)&gKTRexState->phaseFlags |= mask;
    }
    mask = (&lbl_803DC270)[gKTRexState->laneIndex];
    if ((gKTRexRuntime->handlerState & 2) != 0)
    {
        gKTRexRuntime->handlerState &= ~2;
        *(int*)&gKTRexState->phaseFlags |= mask;
    }
    if (gKTRexState->laneAltSelect != 0)
    {
        mask = (&lbl_803DC278)[gKTRexState->laneIndex];
    }
    else
    {
        mask = (&lbl_803DC280)[gKTRexState->laneIndex];
    }
    maskI = mask;
    if ((gKTRexRuntime->handlerState & 1) != 0)
    {
        gKTRexRuntime->handlerState &= ~1;
        *(int*)&gKTRexState->phaseFlags |= maskI;
    }
    dx = oneOverTimeDelta * (gKTRexState->posX - (obj)->anim.localPosX);
    dz = oneOverTimeDelta * (gKTRexState->posZ - (obj)->anim.localPosZ);
    ObjAnim_SampleRootCurvePhase(sqrtf(dx * dx + dz * dz), (ObjAnimComponent*)obj,
                                 &runtime->curvePhase);
    (obj)->anim.localPosX = gKTRexState->posX;
    (obj)->anim.localPosZ = gKTRexState->posZ;
    return 0;
}

int ktrex_stateHandlerB02(GameObject* obj, KTRexRuntime* runtime)
{
    u16 dir;
    f32 tmpY;
    int lane;
    MatrixTransform pos;
    f32 mtx[16];

    dir = gKTRexState->timerFA & 1;
    if ((s8)runtime->moveJustStartedA != 0)
    {
        lane = gKTRexState->laneIndex * 2;
        ObjAnim_SetCurrentMove((int)obj, lbl_8032A510[lane + dir], lbl_803E67B8, 0);
        runtime->curvePhase = lbl_8032A528[gKTRexState->laneIndex];
        gKTRexState->homeYaw = (obj)->anim.rotX;
    }
    if ((gKTRexRuntime->handlerState & 4) != 0)
    {
        gKTRexRuntime->handlerState &= ~4;
        *(int*)&gKTRexState->phaseFlags |= 1;
    }
    if ((gKTRexRuntime->handlerState & 2) != 0)
    {
        gKTRexRuntime->handlerState &= ~2;
        *(int*)&gKTRexState->phaseFlags |= 2;
    }
    if ((gKTRexRuntime->handlerState & 1) != 0)
    {
        gKTRexRuntime->handlerState &= ~1;
        *(int*)&gKTRexState->phaseFlags |= 0x40;
    }
    if ((gKTRexRuntime->handlerState & 0x80) != 0)
    {
        gKTRexRuntime->handlerState &= ~0x80;
        *(u32*)&gKTRexState->phaseFlags |= 0x10000LL;
    }
    runtime->unk34C |= 1;
    (*(void (**)(GameObject*, KTRexRuntime*, f32, int))((char*)*gPlayerInterface + 0x20))(obj, runtime, timeDelta, 3);
    pos.rotX = gKTRexState->homeYaw;
    pos.rotY = 0;
    pos.rotZ = 0;
    pos.scale = lbl_803E6818;
    pos.x = lbl_803E67B8;
    pos.y = lbl_803E67B8;
    pos.z = lbl_803E67B8;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, runtime->localOffsetX, lbl_803E67B8,
                          -runtime->localOffsetZ, &(obj)->anim.velocityX, &tmpY,
                          &(obj)->anim.velocityZ);
    if (dir != 0)
    {
        (obj)->anim.rotX =
            lbl_803E681C * (obj)->anim.currentMoveProgress + (f32)(int)gKTRexState->homeYaw;
    }
    else
    {
        (obj)->anim.rotX =
            (f32)(int)gKTRexState->homeYaw - lbl_803E681C * (obj)->anim.currentMoveProgress;
    }
    return 0;
}

void ktrex_init(GameObject* obj, char* arg, int flag)
{
    int* base = (int*)lbl_8032A510;
    int* pA;
    int iv;
    int* pB;
    int* pC;
    KTRexRuntime* rt;
    int i;
    ObjfsaRomCurveDef* cp;
    u8 spawnFlags;
    s16 yaw;
    gKTRexRuntime = (obj)->extra;
    spawnFlags = 0x10;
    if (flag != 0)
    {
        spawnFlags |= 1;
    }
    (*(void (**)(int, char*, void*, int, int, int, u8, f32))((char*)*gBaddieControlInterface + 0x58))(
        (int)obj, arg, gKTRexRuntime, 9, 0xc, 0x100, spawnFlags, lbl_803E684C);
    (obj)->animEventCallback = ktrex_animEventCallback;
    rt = (KTRexRuntime*)gKTRexRuntime;
    (*(void (**)(int, void*, int))((char*)*gPlayerInterface + 0x14))((int)obj, rt, 0);
    rt->unk270 = 2;
    *(int*)&rt->playerObj = 0;
    rt->unk25F = 0;
    rt->unk349 = 0;
    *(u8*)&(obj)->anim.resetHitboxMode |= 0x88;
    ObjHits_EnableObject((int)obj);
    if ((obj)->anim.modelState != NULL)
    {
        (obj)->anim.modelState->flags |= 0x810;
    }
    gKTRexState = gKTRexRuntime->arena;
    gKTRexState->stack = allocModelStruct_800139e8(4, 4);
    yaw = (s16)((s8)arg[0x2a] << 8);
    (obj)->anim.rotX = yaw;
    gKTRexState->homeYaw = yaw;
    i = 0;
    pA = base + 0x4c / 4;
    iv = 0;
    pB = base + 0x3c / 4;
    pC = base + 0x6c / 4;
    base = base + 0x5c / 4;
    for (; i < 4; i++)
    {
        cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*pA);
        if (cp != NULL)
        {
            *(f32*)((char*)gKTRexState + iv + 0x10) = cp->x;
            *(f32*)((char*)gKTRexState + iv + 0x20) = cp->y;
            *(f32*)((char*)gKTRexState + iv + 0x30) = cp->z;
            cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*pB);
            *(f32*)((char*)gKTRexState + iv + 0x40) = cp->x;
            *(f32*)((char*)gKTRexState + iv + 0x50) = cp->y;
            *(f32*)((char*)gKTRexState + iv + 0x60) = cp->z;
            cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*pC);
            *(f32*)((char*)gKTRexState + iv + 0x70) = cp->x;
            *(f32*)((char*)gKTRexState + iv + 0x80) = cp->y;
            *(f32*)((char*)gKTRexState + iv + 0x90) = cp->z;
            cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*base);
            *(f32*)((char*)gKTRexState + iv + 0xa0) = cp->x;
            *(f32*)((char*)gKTRexState + iv + 0xb0) = cp->y;
            *(f32*)((char*)gKTRexState + iv + 0xc0) = cp->z;
        }
        pA++;
        iv += 4;
        pB++;
        pC++;
        base++;
    }
    gKTRexState->rowAX = (char*)gKTRexState + 0x10;
    gKTRexState->rowAY = (char*)gKTRexState + 0x20;
    gKTRexState->rowAZ = (char*)gKTRexState + 0x30;
    gKTRexState->rowBX = (char*)gKTRexState + 0x40;
    gKTRexState->rowBY = (char*)gKTRexState + 0x50;
    gKTRexState->rowBZ = (char*)gKTRexState + 0x60;
    gKTRexState->phaseCountdown = 4;
    rt->hitCountdown = 3;
    gKTRexResource = Resource_Acquire(0x5a, 1);
    (obj)->unkF8 = 0;
    gKTRexMapBlock = mapBlockFn_800592e4();
    gKTRexState->light = objCreateLight(0, 1);
    if (gKTRexState->light != 0)
    {
        modelLightStruct_setLightKind(gKTRexState->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(gKTRexState->light, (obj)->anim.localPosX,
                                     (obj)->anim.localPosY, (obj)->anim.localPosZ);
        modelLightStruct_setDiffuseColor(gKTRexState->light, 0xff, 0, 0, 0);
        modelLightStruct_setDistanceAttenuation(gKTRexState->light, lbl_803E6850, lbl_803E67F0);
        modelLightStruct_setupGlow(gKTRexState->light, 0, 0xff, 0, 0, 0x50, lbl_803E67F0);
        modelLightStruct_setGlowProjectionRadius(gKTRexState->light, lbl_803E67BC);
    }
    streamFn_8000a380(3, 2, 0x1f4);
}

void ktrex_updateAttackEffects(GameObject* obj)
{
    int i;
    f32 mag;
    mag = lbl_803E6818 - gKTRexRuntime->playerDist / lbl_803E6824;
    if (mag < lbl_803E67B8)
    {
        mag = lbl_803E67B8;
    }
    else if (mag > lbl_803E6818)
    {
        mag = lbl_803E6818;
    }
    if ((gKTRexState->phaseFlags & 0x40) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexroarsht11);
    }
    if ((gKTRexState->phaseFlags & 0x80) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexroarmed11);
    }
    if ((gKTRexState->phaseFlags & 0x100) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexroarlng11);
    }
    if ((gKTRexState->phaseFlags & 0x200) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexexhale16);
    }
    if ((gKTRexState->phaseFlags & 0x10000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_fireup_c);
    }
    if ((gKTRexState->phaseFlags & 0x40000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexthrash11);
    }
    if ((gKTRexState->phaseFlags & 0x80000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexhurt12);
    }
    if ((gKTRexState->phaseFlags & 0x2000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexhurt12);
    }
    if ((gKTRexState->phaseFlags & 0x1000) != 0)
    {
        gKTRexState->phaseFlags &= ~0x1800LL;
    }
    if ((gKTRexState->phaseFlags & 0x20000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_fireup_c);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E67C8 * mag);
    }
    if ((gKTRexState->timerFA & 0x10) != 0)
    {
        for (i = 0; i < KTREX_LIGHTNING_COUNT; i++)
        {
            if ((int)randomGetRange(0, 5) == 0 && gKTRexState->lightning[i] == NULL)
            {
                ktrex_spawnRandomEnergyArc((int)obj, randomGetRange(8, 0xc), lbl_803E6828, i);
            }
        }
    }
    if ((gKTRexState->phaseFlags & 0x4000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexbreathin11);
        gKTRexState->laneAltSelect ^= 1;
    }
    if ((gKTRexState->phaseFlags & 0x8000) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexbreathout11);
        gKTRexState->laneAltSelect ^= 1;
    }
    if ((gKTRexState->phaseFlags & 0x3) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexfoot11);
        doRumble(lbl_803E67CC);
        if (mag > lbl_803E67B4)
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(mag);
            mainSetBits(0x554, 1);
        }
    }
    if ((gKTRexState->phaseFlags & 0xc) != 0)
    {
        doRumble(lbl_803E682C);
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexfoot11_91);
        if (mag > lbl_803E67B4)
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E67C8 * mag);
            mainSetBits(0x554, 1);
        }
    }
    if ((gKTRexState->phaseFlags & 0x30) != 0)
    {
        doRumble(lbl_803E6830);
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexfoot11_92);
        if (mag > lbl_803E67B4)
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6834 * mag);
            mainSetBits(0x554, 1);
        }
    }
    if ((gKTRexState->phaseFlags & 0x100000) == 0)
    {
        gKTRexState->phaseFlags &= 0x1800LL;
        return;
    }
    if ((gKTRexState->phaseFlags & 0x1) != 0)
    {
        gKTRexState->unk12C = lbl_803E6818;
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x2) != 0)
    {
        gKTRexState->unk144 = lbl_803E6818;
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x4) != 0)
    {
        gKTRexState->unk12C = lbl_803E6838;
        for (i = 0; i < 13; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x8) != 0)
    {
        gKTRexState->unk144 = lbl_803E6838;
        for (i = 0; i < 13; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x10) != 0)
    {
        gKTRexState->unk12C = lbl_803E67C8;
        for (i = 0; i < 16; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x124, 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x20) != 0)
    {
        gKTRexState->unk144 = lbl_803E67C8;
        for (i = 0; i < 16; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x13c, 0x200001, -1, NULL);
        }
    }
    if ((gKTRexState->phaseFlags & 0x800) != 0)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, 0x487, (char*)gKTRexState + 0x10c, 0x200001, -1, (char*)gKTRexState + 0x16c);
    }
    gKTRexState->phaseFlags &= 0x1800LL;
    if (((ObjHitsPriorityState*)(obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject())
    {
        Sfx_PlayFromObject((int)Obj_GetPlayerObject(), SFXTRIG_mv_bflconc1_2b9);
    }
}

void ktrex_updateContactEffects(GameObject* obj, KTRexRuntime* runtime)
{
    int hitType;
    u32 hitC;
    int hitA;
    int msg[4];
    int hit;
    f32* contactPoints;
    f32* pt;
    *(KtrexMsgBlob*)msg = gKTRexMsgTemplate;
    if (gKTRexContactEffectCooldown != 0)
    {
        gKTRexContactEffectCooldown -= 1;
    }
    if (gKTRexRuntime->bobPhase > lbl_803E67B8)
    {
        gKTRexRuntime->bobPhase =
            timeDelta * gKTRexRuntime->bobRate + gKTRexRuntime->bobPhase;
        if (gKTRexRuntime->bobPhase < lbl_803E67B8)
        {
            gKTRexRuntime->bobPhase = lbl_803E67B8;
        }
        else if (gKTRexRuntime->bobPhase > lbl_803E6820)
        {
            gKTRexRuntime->bobPhase =
                lbl_803E6820 - (gKTRexRuntime->bobPhase - lbl_803E6820);
            gKTRexRuntime->bobRate = -gKTRexRuntime->bobRate;
        }
    }
    hit = ObjHits_GetPriorityHit(obj, &hitA, &hitType, &hitC);
    if (hit == 0)
    {
        return;
    }
    contactPoints = *(f32**)((u8*)((ObjAnimComponent*)obj)->banks[((ObjAnimComponent*)obj)->bankIndex] + 0x50);
    if ((s8)runtime->hitCountdown != 0 && (hitType == 3 || hitType == 2) &&
        (gKTRexState->timerFA & 0x10) != 0 && hit == 5)
    {
        gKTRexEffectSpawnWork.posX = playerMapOffsetX + (pt = contactPoints + hitType * 4)[1];
        gKTRexEffectSpawnWork.posY = pt[2];
        gKTRexEffectSpawnWork.posZ = playerMapOffsetZ + pt[3];
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexhurt12);
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_stftest122);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b2, &gKTRexEffectSpawnWork, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b3, &gKTRexEffectSpawnWork, 0x200001, -1, NULL);
        if (hit == 0xe)
        {
            runtime->hitCountdown -= 1;
        }
        else
        {
            runtime->hitCountdown = 0;
        }
        if ((s8)runtime->hitCountdown <= 0)
        {
            runtime->hitCountdown = 0;
            gKTRexState->timerFA &= ~0x10;
            gKTRexState->timerFA |= 0x8;
        }
        runtime->unk34F = hit;
    }
    else if (gKTRexContactEffectCooldown == 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_95);
        contactPoints = KTRex_GetActiveContactPointTable(obj);
        gKTRexEffectSpawnWork.posX = contactPoints[hitType * 4 + 1] + playerMapOffsetX;
        gKTRexEffectSpawnWork.posY = contactPoints[hitType * 4 + 2];
        gKTRexEffectSpawnWork.posZ = contactPoints[hitType * 4 + 3] + playerMapOffsetZ;
        (*gPartfxInterface)->spawnObject((void*)obj, KTREX_PARTFX_HIT, &gKTRexEffectSpawnWork, 0x200001, -1, NULL);
        gKTRexEffectSpawnWork.posX -= obj->anim.worldPosX;
        gKTRexEffectSpawnWork.posY -= obj->anim.worldPosY;
        gKTRexEffectSpawnWork.posZ -= obj->anim.worldPosZ;
        gKTRexEffectSpawnWork.unk8 = lbl_803E6818;
        gKTRexEffectSpawnWork.unk0 = 0;
        gKTRexEffectSpawnWork.unk2 = 0;
        gKTRexEffectSpawnWork.unk4 = 0;
        msg[1] += randomGetRange(0, 0x9b);
        msg[2] += randomGetRange(0, 0x9b);
        (*(void (**)(void*, int, void*, int, int, int*))(*(int*)gKTRexResource + 0x4))(obj, 0, &gKTRexEffectSpawnWork, 1,
                                                                                       -1, msg);
        gKTRexContactEffectCooldown = 0x3c;
    }
    if ((s8)runtime->hitCountdown < 1)
    {
        runtime->hitCountdown = 0;
    }
    ObjMsg_SendToObject((void*)hitA, KTREX_ADVANCE_MSG, obj, 0);
}

int ktrex_stateHandlerA02(GameObject* obj, KTRexRuntime* runtime)
{
    void* p;
    u16 flags;
    u8 phase;
    int idx;
    int flag1;
    u8* pb;
    p = ((GameObject*)obj)->anim.placementData;
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 1);
        gKTRexState->laneIndex = 0;
        gKTRexState->timerFA &= ~0x20;
        {
            u8* row = (u8*)p + 0x38;
            runtime->laneSpeed =
                *(f32*)(row + gKTRexState->laneIndex * 4) / lbl_803E67C4;
        }
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        int push = 2;
        if (Stack_IsFull(gKTRexState->stack) == 0)
        {
            Stack_Push(gKTRexState->stack, &push);
        }
        return 4;
    }
    flags = gKTRexState->timerFA;
    flag1 = flags & 1;
    if (gKTRexState->laneIndex == 0 &&
        (phase = gKTRexState->phaseCounter) >= 2 && (flags & 0x20) == 0 &&
        ((flag1 == 0 && gKTRexState->laneLerpT >= lbl_803E67E8) ||
         (flag1 != 0 && gKTRexState->laneLerpT <= lbl_803E67C0)))
    {
        idx = phase >> 1;
        pb = (u8*)p;
        if ((int)randomGetRange(0, 0x64) <= pb[idx + 0x56])
        {
            int push;
            gKTRexState->pathCountdown = 2;
            push = 5;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &push);
            }
            gKTRexState->moveVariant = 1;
            return 5;
        }
        if ((int)randomGetRange(0, 0x64) <= pb[idx + 0x52])
        {
            u8 cond;
            u8 fe = gKTRexState->currentLaneMask;
            if (fe == 1)
            {
                cond = gKTRexState->activeLaneMask == 2;
            }
            else if (fe == 2)
            {
                cond = gKTRexState->activeLaneMask == 1;
            }
            else if (fe == 4)
            {
                cond = gKTRexState->activeLaneMask == 8;
            }
            else
            {
                cond = gKTRexState->activeLaneMask == 4;
            }
            if (cond && (gKTRexState->timerFA & 0x40) == 0)
            {
                int push;
                gKTRexState->moveVariant = 0;
                push = 0xb;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
                return 5;
            }
        }
        gKTRexState->timerFA |= 0x20;
    }
    if ((gKTRexState->currentLaneMask & gKTRexState->activeLaneMask) != 0)
    {
        gKTRexState->timerFA &= ~0x40;
        {
            u8 result;
            if ((gKTRexState->currentLaneMask & gKTRexState->activeLaneMask) !=
                0)
            {
                if ((gKTRexState->timerFA & 1) != 0)
                {
                    if (gKTRexState->laneLerpT - gKTRexState->laneFrac >
                        lbl_803E67B4)
                    {
                        result = 1;
                        goto haveResult;
                    }
                }
                else
                {
                    if (gKTRexState->laneFrac - gKTRexState->laneLerpT >
                        lbl_803E67B4)
                    {
                        result = 1;
                        goto haveResult;
                    }
                }
            }
            result = 0;
        haveResult:;
            if (result != 0)
            {
                int push;
                gKTRexState->pathCountdown = 1;
                push = 5;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
                gKTRexState->moveVariant = 1;
                return 5;
            }
        }
    }
    return 0;
}

int ktrex_stateHandlerA03(GameObject* obj, KTRexRuntime* runtime)
{
    int phase;
    f32 f4;
    f32 f5;
    int popped;
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 2);
        goto ret0;
    }
    if ((s8)runtime->moveDone != 0)
    {
        phase = (gKTRexState->timerFA >> 1) & 3;
        f5 = ((f32*)*(int*)&gKTRexState->rowBX)[phase] -
             ((f32*)*(int*)&gKTRexState->rowAX)[phase];
        f4 = ((f32*)*(int*)&gKTRexState->rowBZ)[phase] -
             ((f32*)*(int*)&gKTRexState->rowAZ)[phase];
        if (__fabs(f5) > __fabs(f4))
        {
            f4 = (((GameObject*)obj)->anim.localPosX - ((f32*)*(int*)&gKTRexState->rowAX)[phase]) /
                 f5;
        }
        else
        {
            f4 = (((GameObject*)obj)->anim.localPosZ - ((f32*)*(int*)&gKTRexState->rowAZ)[phase]) /
                 f4;
        }
        gKTRexState->laneLerpT = f4;
        popped = 0;
        if (Stack_IsEmpty(gKTRexState->stack) == 0)
        {
            Stack_Pop(gKTRexState->stack, &popped);
        }
        return popped + 1;
    }
ret0:
    return 0;
}

int ktrex_stateHandlerA07(GameObject* obj, KTRexRuntime* runtime)
{
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 6);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        gKTRexState->phaseCounter += 1;
        ktrexlevel_clearPathGameBits();
        mainSetBits(GAMEBIT_DR_KTrexPhaseCounter, gKTRexState->phaseCounter);
        gKTRexState->timerFA |= 0x10;
        gKTRexState->timerFA &= ~8;
        Music_Trigger(MUSICTRIG_guard_theme, 0);
        Music_Trigger(MUSICTRIG_mammoth_walk, 0);
        Music_Trigger(MUSICTRIG_menu_page, 1);
    }
    else if ((s8)runtime->moveDone != 0 || (gKTRexState->timerFA & 8) != 0)
    {
        return 9;
    }
    return 0;
}

int ktrex_stateHandlerA04(GameObject* obj, KTRexRuntime* runtime)
{
    void* p;
    int popped;
    f32 timer;
    p = ((GameObject*)obj)->anim.placementData;
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 4);
        gKTRexState->stateTimer =
            (f32)(u32)((u16*)((char*)p + 0x44))[gKTRexState->moveVariant];
    }
    else
    {
        timer = gKTRexState->stateTimer - timeDelta;
        gKTRexState->stateTimer = timer;
        if (timer < lbl_803E67B8)
        {
            gKTRexState->stateTimer = lbl_803E67B8;
        }
        if ((s8)runtime->moveDone != 0)
        {
            if (gKTRexState->stateTimer <= lbl_803E67B8)
            {
                popped = 0;
                if (Stack_IsEmpty(gKTRexState->stack) == 0)
                {
                    Stack_Pop(gKTRexState->stack, &popped);
                }
                return popped + 1;
            }
        }
    }
    return 0;
}

int ktrex_stateHandlerA05(GameObject* obj, KTRexRuntime* runtime)
{
    void* p;
    int pushLo;
    int pushHi;
    p = (obj)->anim.placementData;
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 1);
        gKTRexState->laneIndex = 1;
        p = (char*)p + gKTRexState->laneIndex * 4;
        runtime->laneSpeed = ((KtrexPlacement*)p)->laneSpeed / lbl_803E67C4;
    }
    if (RandomTimer_UpdateRangeTrigger((char*)gKTRexState + 0x190, lbl_803E67C8, lbl_803E67CC) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexbreathout11);
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        gKTRexState->pathCountdown -= 1;
        if ((s8)gKTRexState->pathCountdown <= 0)
        {
            pushLo = 2;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &pushLo);
            }
        }
        else
        {
            pushHi = 5;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &pushHi);
            }
        }
        return 4;
    }
    if (ktrex_isPlayerInLaneThreatRange(obj) != 0)
    {
        return 8;
    }
    return 0;
}

int ktrex_stateHandlerA08(GameObject* obj, KTRexRuntime* runtime)
{
    void* p;
    f32 timer;
    p = ((GameObject*)obj)->anim.placementData;
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 7);
        {
            u8* row = (u8*)p + 0x4a;
            gKTRexState->stateTimer =
                (f32)(u32) * (u16*)(row + (gKTRexState->phaseCounter & ~1));
        }
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        goto ret0;
    }
    if ((gKTRexState->timerFA & 8) == 0)
    {
        timer = gKTRexState->stateTimer - timeDelta;
        gKTRexState->stateTimer = timer;
        if (!(timer <= lbl_803E67B8))
        {
            goto ret0;
        }
    }
    if ((gKTRexState->timerFA & 8) != 0)
    {
        gKTRexState->phaseCountdown -= 1;
        runtime->hitCountdown = 3;
    }
    gKTRexState->timerFA &= ~0x10;
    if (gKTRexState->phaseCountdown == 0)
    {
        return 2;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    return 10;
ret0:
    return 0;
}

int ktrex_stateHandlerA11(GameObject* obj, KTRexRuntime* runtime)
{
    int phase;
    f32 f4;
    f32 f5;
    if ((gKTRexState->timerFA & 1) != 0u)
    {
        obj->anim.rotX = (s16)(obj->anim.rotX + 0x8000);
    }
    else
    {
        obj->anim.rotX = (s16)(obj->anim.rotX - 0x8000);
    }
    gKTRexState->timerFA ^= 1;
    if ((gKTRexState->timerFA & 1) != 0)
    {
        gKTRexState->rowAX = (char*)gKTRexState + 0x70;
        gKTRexState->rowAY = (char*)gKTRexState + 0x80;
        gKTRexState->rowAZ = (char*)gKTRexState + 0x90;
        gKTRexState->rowBX = (char*)gKTRexState + 0xa0;
        gKTRexState->rowBY = (char*)gKTRexState + 0xb0;
        gKTRexState->rowBZ = (char*)gKTRexState + 0xc0;
    }
    else
    {
        gKTRexState->rowAX = (char*)gKTRexState + 0x10;
        gKTRexState->rowAY = (char*)gKTRexState + 0x20;
        gKTRexState->rowAZ = (char*)gKTRexState + 0x30;
        gKTRexState->rowBX = (char*)gKTRexState + 0x40;
        gKTRexState->rowBY = (char*)gKTRexState + 0x50;
        gKTRexState->rowBZ = (char*)gKTRexState + 0x60;
    }
    phase = (gKTRexState->timerFA >> 1) & 3;
    f5 = ((f32*)*(int*)&gKTRexState->rowBX)[phase] -
         ((f32*)*(int*)&gKTRexState->rowAX)[phase];
    f4 = ((f32*)*(int*)&gKTRexState->rowBZ)[phase] -
         ((f32*)*(int*)&gKTRexState->rowAZ)[phase];
    if (__fabs(f5) > __fabs(f4))
    {
        f4 = (obj->anim.localPosX - ((f32*)*(int*)&gKTRexState->rowAX)[phase]) / f5;
    }
    else
    {
        f4 = (obj->anim.localPosZ - ((f32*)*(int*)&gKTRexState->rowAZ)[phase]) / f4;
    }
    gKTRexState->laneLerpT = f4;
    gKTRexState->timerFA |= 0x40;
    return 3;
}

int ktrex_stateHandlerA09(GameObject* obj, KTRexRuntime* runtime)
{
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 8);
        if ((*gCameraInterface)->getMode() == CAMMODE_DEFAULT)
        {
            (*gCameraInterface)->loadTriggeredCamAction(2, 0, 0);
        }
    }
    else if ((s8)runtime->moveDone != 0)
    {
        gKTRexState->lastPhase = (gKTRexState->timerFA >> 1) & 3;
        gKTRexState->stateTimer = lbl_803E67D8;
        Music_Trigger(MUSICTRIG_menu_page, 0);
        Music_Trigger(MUSICTRIG_guard_theme, 1);
        return 11;
    }
    return 0;
}

int ktrex_stateHandlerA10(GameObject* obj, KTRexRuntime* runtime)
{
    void* p;
    u16 flags;
    int phase;
    int laneBit;
    p = (obj)->anim.placementData;
    flags = gKTRexState->timerFA;
    phase = (flags >> 1) & 3;
    laneBit = flags & 1;
    if ((s8)runtime->moveJustStartedB != 0)
    {
        (*(void (**)(GameObject*, KTRexRuntime*, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 1);
        gKTRexState->laneIndex = 2;
        {
            u8* row = (u8*)p + 0x38;
            runtime->laneSpeed =
                *(f32*)(row + gKTRexState->laneIndex * 4) / lbl_803E67C4;
        }
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        int push = 0xa;
        if (Stack_IsFull(gKTRexState->stack) == 0)
        {
            Stack_Push(gKTRexState->stack, &push);
        }
        return 4;
    }
    if ((u8)ktrex_shouldAdvanceArenaPhase() != 0)
    {
        (*gCameraInterface)->loadTriggeredCamAction(3, 0, 0);
    }
    if (RandomTimer_UpdateRangeTrigger((char*)gKTRexState + 0x190, lbl_803E67C8, lbl_803E67CC) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_rexbreathout11);
    }
    {
        f32 u4 = gKTRexState->stateTimer - timeDelta;
        gKTRexState->stateTimer = u4;
        if (u4 <= lbl_803E67B8)
        {
            gKTRexState->stateTimer = *(f32*)&lbl_803E67B8;
        }
    }
    if (gKTRexState->stateTimer <= lbl_803E67B8 &&
        gKTRexState->lastPhase == phase &&
        ((laneBit == 0 && gKTRexState->laneLerpT >= lbl_803E67D0) ||
         (laneBit != 0 && gKTRexState->laneLerpT <= lbl_803E67D4)))
    {
        if ((gKTRexState->timerFA & 8) != 0)
        {
            u8 cond;
            u8 fe;
            gKTRexState->phaseCounter += 1;
            mainSetBits(GAMEBIT_DR_KTrexPhaseCounter, gKTRexState->phaseCounter);
            gKTRexState->moveVariant = 0;
            gKTRexState->timerFA &= ~0x8;
            fe = gKTRexState->currentLaneMask;
            if (fe == 1)
            {
                cond = gKTRexState->activeLaneMask == 2;
            }
            else if (fe == 2)
            {
                cond = gKTRexState->activeLaneMask == 1;
            }
            else if (fe == 4)
            {
                cond = gKTRexState->activeLaneMask == 8;
            }
            else
            {
                cond = gKTRexState->activeLaneMask == 4;
            }
            if (cond && (gKTRexState->timerFA & 0x40) == 0)
            {
                int push = 0xb;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
            }
            else
            {
                int push = 2;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
            }
            {
                int push = 4;
                if (Stack_IsFull(gKTRexState->stack) == 0)
                {
                    Stack_Push(gKTRexState->stack, &push);
                }
            }
        }
        else
        {
            int push;
            gKTRexState->phaseCounter -= 1;
            push = 2;
            if (Stack_IsFull(gKTRexState->stack) == 0)
            {
                Stack_Push(gKTRexState->stack, &push);
            }
        }
        ktrexlevel_updatePathGameBits();
        (*gCameraInterface)->loadTriggeredCamAction(3, 0, 0);
        mainSetBits(GAMEBIT_DR_KTrexPhaseCounter, gKTRexState->phaseCounter);
        {
            int popped = 0;
            if (Stack_IsEmpty(gKTRexState->stack) == 0)
            {
                Stack_Pop(gKTRexState->stack, &popped);
            }
            return popped + 1;
        }
    }
    return 0;
}

int ktrex_stateHandlerA01(GameObject* obj, KTRexRuntime* runtime)
{
    if ((s8)runtime->moveJustStartedB != 0)
    {
        *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        runtime->unk349 = 0;
        runtime->unk25F = 0;
        gKTRexState->stateTimer = lbl_803E67EC;
    }
    else
    {
        gKTRexState->stateTimer -= timeDelta;
        if (gKTRexState->stateTimer <= lbl_803E67F0)
        {
            if (obj->unkF8 != 3)
            {
                (*gScreenTransitionInterface)->start(30, 1);
                obj->unkF8 = 3;
            }
        }
        if (gKTRexState->stateTimer <= lbl_803E67B8)
        {
            Obj_SetModelColorFadeRecursive(Obj_GetPlayerObject(), 0, 0, 0, 0, 0);
            Music_Trigger(MUSICTRIG_mammoth_walk, 0);
            Music_Trigger(MUSICTRIG_menu_page, 0);
            Music_Trigger(MUSICTRIG_guard_theme, 0);
            ((ObjAnimComponent*)obj)->bankIndex = 1;
            mainSetBits(GAMEBIT_WC_Unk0564, 1);
            mainSetBits(GAMEBIT_WC_ObjGroups, 0);
            (*gMapEventInterface)->setObjGroupStatus(13, 0, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 1, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 5, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 10, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 11, 1);
            mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
            unlockLevel(53, 1, 0);
            mainSetBits(GAMEBIT_ITEM_FireSpellStone2_Got, 1);
            (*gMapEventInterface)->setMapAct(4, 2);
        }
    }
    return 0;
}

f32 gKTRexLaneSpeedMin[3] = {0.0f, 0.025f, 0.025f};

f32 gKTRexLaneSpeedMax[19] = {
    1.0f,         0.975f,       0.975f,       2.8742e-40f,  2.8743e-40f,  2.87401e-40f, 2.8741e-40f,
    2.87412e-40f, 2.87422e-40f, 2.87394e-40f, 2.87402e-40f, 2.88206e-40f, 2.88209e-40f, 2.8821e-40f,
    2.88204e-40f, 2.87415e-40f, 2.87425e-40f, 2.87395e-40f, 2.87405e-40f,
};

/* descriptor/ptr table auto 0x8032a58c-0x8032a7c0 */
u32 gKtRexObjDescriptor[17] = {0x00000000,
                               0x00000000,
                               0x00000000,
                               0x000b0000,
                               (u32)ktrex_initialise,
                               (u32)ktrex_release,
                               0x00000000,
                               (u32)ktrex_init,
                               (u32)ktrex_update,
                               (u32)ktrex_hitDetect,
                               (u32)ktrex_render,
                               (u32)ktrex_free,
                               (u32)ktrex_getObjectTypeId,
                               (u32)ktrex_getExtraSize,
                               (u32)ktrex_setScale,
                               (u32)ktrex_func0B,
                               0x00000000};
u32 gKtRexFloorSwitchObjDescriptor[14] = {0x00000000,
                                          0x00000000,
                                          0x00000000,
                                          0x00090000,
                                          (u32)KT_RexFloorSwitch_initialise,
                                          (u32)KT_RexFloorSwitch_release,
                                          0x00000000,
                                          (u32)KT_RexFloorSwitch_init,
                                          (u32)KT_RexFloorSwitch_update,
                                          (u32)KT_RexFloorSwitch_hitDetect,
                                          (u32)KT_RexFloorSwitch_render,
                                          (u32)KT_RexFloorSwitch_free,
                                          (u32)KT_RexFloorSwitch_getObjectTypeId,
                                          (u32)KT_RexFloorSwitch_getExtraSize};
u32 gKtLazerwallObjDescriptor[14] = {0x00000000,
                                     0x00000000,
                                     0x00000000,
                                     0x00090000,
                                     (u32)KT_Lazerwall_initialise,
                                     (u32)KT_Lazerwall_release,
                                     0x00000000,
                                     (u32)KT_Lazerwall_init,
                                     (u32)KT_Lazerwall_update,
                                     (u32)KT_Lazerwall_hitDetect,
                                     (u32)KT_Lazerwall_render,
                                     (u32)KT_Lazerwall_free,
                                     (u32)KT_Lazerwall_getObjectTypeId,
                                     (u32)KT_Lazerwall_getExtraSize};
u32 gKtLazerlightObjDescriptor[14] = {0x00000000,
                                      0x00000000,
                                      0x00000000,
                                      0x00090000,
                                      (u32)ktlazerlight_initialise,
                                      (u32)ktlazerlight_release,
                                      0x00000000,
                                      (u32)ktlazerlight_init,
                                      (u32)ktlazerlight_update,
                                      (u32)ktlazerlight_hitDetect,
                                      (u32)ktlazerlight_render,
                                      (u32)ktlazerlight_free,
                                      (u32)ktlazerlight_getObjectTypeId,
                                      (u32)ktlazerlight_getExtraSize};
u32 gKtFallingrocksObjDescriptor[14] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x00090000,
                                        (u32)ktfallingrocks_initialise,
                                        (u32)ktfallingrocks_release,
                                        0x00000000,
                                        (u32)ktfallingrocks_init,
                                        (u32)ktfallingrocks_update,
                                        (u32)ktfallingrocks_hitDetect,
                                        (u32)ktfallingrocks_render,
                                        (u32)ktfallingrocks_free,
                                        (u32)ktfallingrocks_getObjectTypeId,
                                        (u32)ktfallingrocks_getExtraSize};
u32 gDrLaserCannonObjDescriptor[14] = {0x00000000,
                                       0x00000000,
                                       0x00000000,
                                       0x00090000,
                                       (u32)DR_LaserCannon_initialise,
                                       (u32)DR_LaserCannon_release,
                                       0x00000000,
                                       (u32)DR_LaserCannon_init,
                                       (u32)DR_LaserCannon_update,
                                       (u32)DR_LaserCannon_hitDetect,
                                       (u32)DR_LaserCannon_render,
                                       (u32)DR_LaserCannon_free,
                                       (u32)DR_LaserCannon_getObjectTypeId,
                                       (u32)DR_LaserCannon_getExtraSize};
u32 gDrakorMissileObjDescriptor[18] = {0x00000000,
                                       0x00000000,
                                       0x00000000,
                                       0x000d0000,
                                       (u32)drakormissile_initialise,
                                       (u32)drakormissile_release,
                                       0x00000000,
                                       (u32)drakormissile_init,
                                       (u32)drakormissile_update,
                                       (u32)drakormissile_hitDetect,
                                       (u32)drakormissile_render,
                                       (u32)drakormissile_free,
                                       (u32)drakormissile_getObjectTypeId,
                                       (u32)drakormissile_getExtraSize,
                                       (u32)drakormissile_setScale,
                                       (u32)drakormissile_startStraightLaunch,
                                       (u32)drakormissile_modelMtxFn,
                                       (u32)drakormissile_abortStraightFlight};
s16 lbl_8032A730[44] = {0x0ddc, 0x0de2, 0x0dde, 0x0ddd, 0x0de0, 0x0de3, 0x0ddf, 0x0de1, 0x0de4, 0x0000, 0x0de5,
                        0x0deb, 0x0de7, 0x0de6, 0x0de9, 0x0dec, 0x0de8, 0x0dea, 0x0ded, 0x0000, 0x0f34, 0x0f3a,
                        0x0f36, 0x0f35, 0x0f38, 0x0f3b, 0x0f37, 0x0f39, 0x0000, 0x0524, 0x0000, 0x0524, 0x0000,
                        0x0524, 0x0000, 0x0571, 0x0000, 0x056e, 0x0000, 0x056f, 0x0000, 0x0570, 0x0000, 0x0572};
u32 gGmMazeWellObjDescriptor[14] = {0x00000000,
                                    0x00000000,
                                    0x00000000,
                                    0x00090000,
                                    0x00000000,
                                    0x00000000,
                                    0x00000000,
                                    (u32)GM_MazeWell_init,
                                    (u32)GM_MazeWell_update,
                                    0x00000000,
                                    (u32)GM_MazeWell_render,
                                    (u32)GM_MazeWell_free,
                                    0x00000000,
                                    (u32)GM_MazeWell_getExtraSize};
