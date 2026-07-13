/*
 * bossdrakor (DLL 0x24D) - the boss dragon "Drakor" encounter object.
 *
 * Drives the flying boss: it follows ROM curve paths to move, smooth-turns
 * toward its velocity or yaws to face the player, advances animation moves,
 * and runs a small move-state machine (BossDrakorState.moveState) that
 * sequences attack/recover animations. b40 in the DrakorFlags byte (state
 * +0x198) marks the active "combat/flight" phase; other bits gate hit
 * handling (b04/b08), the first-frame setup (b10), and the air-meter HUD
 * (b20).
 *
 * On first update (b10) it spawns env fx, restores the sky/time-of-day,
 * (re)initialises the curve follower from its saved home position, and
 * creates a glow light (lightObj). Attacks spawn missile/breath objects via
 * Obj_AllocObjectSetup + loadObjectAtObject, aimed at the player with random
 * spread. Hits (priority hit 0xE/0xF) decrement airMeterHandle; when it
 * drops below zero the boss explodes, is removed from the update list, sets
 * map-act 0x1d=3 and game bit 0x83c, and grants the defeat bit stored in the
 * placement (defeatedGameBit). Defeat anim events warp to map 0x79 and restore the HUD.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/DR/dll_80209FE0_shared.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/music_api.h"
#include "main/gametext_show_api.h"
#include "main/rcp_dolphin.h"
#include "main/rcp_dolphin_api.h"
#include "main/maketex_api.h"
#include "main/maketex_random_api.h"
#include "main/maketex_timer_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/dll_0262_drakormissile.h"
#include "main/dll/dll_0271_drakorhoverpad.h"
#include "main/render.h"
#include "main/object.h"
#include "main/object_update_list.h"
#include "main/obj_placement.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_api.h"
#include "main/objprint_sound_api.h"
#include "main/object_render.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/modellight_api.h"
#include "main/objfx.h"
#include "main/dll/objfx_api.h"
#include "main/sky_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/dll/dll_024D_bossdrakor.h"

#define ObjGroup_FindNearestObjectLegacy(group, obj, distance) \
    ((int (*)())ObjGroup_FindNearestObject)((group), (obj), (distance))
#define ObjLink_AttachChildLegacy(parent, child, mode) \
    ((u64 (*)())ObjLink_AttachChild)((parent), (child), (mode))

#define BOSSDRAKOR_MAP_ARENA          0x1d /* map-event id set to act 3 on boss defeat */
#define BOSSDRAKOR_OBJGROUP           0x45
#define BOSSDRAKOR_PARTFX             0x7ad
#define BOSSDRAKOR_HIT_VOLUME_SLOT    5
#define BOSSDRAKOR_AIRMETER_BGTEXTURE 0x63e /* HUD air-meter background texture id */
/* groups owned by other DLLs, queried here */
#define DRAKORHOVERPAD_OBJGROUP 0x46 /* DLL 0x271 drakorhoverpad */
#define DBHOLECONTROL1_OBJGROUP 0x1e /* DLL 0x243 dbholecontrol1 */

#define MODEL_LIGHT_KIND_POINT 2

/* object-type ids of the attack children Drakor spawns (see file docblock). */
#define BOSSDRAKOR_CHILD_OBJ_MISSILE 0x70f /* drakormissile (drakormissile_startActiveLaunch) */
#define BOSSDRAKOR_CHILD_OBJ_ATTACK  0x709 /* spawnAttackObjects: BossdrakorPlacement (airMeterMax/curveStartIndex) */

#define BOSSDRAKOR_OBJFLAG_RENDERED 0x800

/* env effects co-activated on first-frame setup (b10); opaque distinct roles */
#define BOSSDRAKOR_ENVFX_A 0x144
#define BOSSDRAKOR_ENVFX_B 0x10d
#define BOSSDRAKOR_ENVFX_C 0x10e

void bossdrakor_release(void)
{
}

void bossdrakor_initialise(void)
{
}

int bossdrakor_getExtraSize(void)
{
    return 0x1a4;
}

#pragma opt_common_subs off

#pragma opt_propagation off
void bossdrakor_update(int obj)
{
    int state;
    s8* p;
    int i;
    int state2;
    int moveResult;
    int adv;
    int player;
    int moveId;
    s16* uvec;
    s16 shakeX;
    s16 shakeY;
    int* tbl;
    int* tblRes;
    f32 shake;
    f32 shakeScaleZ;
    f32 t;
    f32 spd;
    s16 d;
    int step;
    s16* vec;
    s8 buf[0x1c];
    f32 hz;
    f32 hy;
    f32 hx;
    int curveArg;

    state = *(int*)&((GameObject*)obj)->extra;
    curveArg = 0x29;
    if (((DrakorFlags*)((char*)state + 0x198))->b10)
    {
        getEnvfxActImmediatelyInt(obj, obj, BOSSDRAKOR_ENVFX_A, 0);
        getEnvfxActImmediatelyInt(obj, obj, BOSSDRAKOR_ENVFX_B, 0);
        getEnvfxActImmediatelyInt(obj, obj, BOSSDRAKOR_ENVFX_C, 0);
        skyFn_80088e54(1, lbl_803E6510);
        timeOfDayFn_80055038();
        if ((*gRomCurveInterface)->initCurve((void*)((char*)state + 0x28), (void*)obj, lbl_803E6560, &curveArg, 0xd) !=
            0)
        {
            (*gRomCurveInterface)->initCurve((void*)((char*)state + 0x28), (void*)obj, lbl_803E6560, &curveArg, 0);
        }
        ((GameObject*)obj)->anim.localPosX = ((BossDrakorState*)state)->savedPosX;
        ((GameObject*)obj)->anim.localPosZ = ((BossDrakorState*)state)->savedPosZ;
        ((GameObject*)obj)->anim.localPosY = ((BossDrakorState*)state)->savedPosY;
        ((DrakorFlags*)((char*)state + 0x198))->b20 = 1;
        ((BossDrakorState*)state)->repeatCount = 0;
        state2 = *(int*)&((GameObject*)obj)->extra;
        ((DrakorFlags*)((char*)state2 + 0x198))->b20 = 1;
        (*gGameUIInterface)->initAirMeter(((BossDrakorState*)state2)->airMeterHandle, BOSSDRAKOR_AIRMETER_BGTEXTURE);
        (*gGameUIInterface)->runAirMeter(((BossDrakorState*)state2)->airMeterHandle);
        ((DrakorFlags*)((char*)state + 0x198))->b10 = 0;
        ((BossDrakorState*)state)->lightObj = objCreateLight(NULL, 1);
        if (((BossDrakorState*)state)->lightObj != NULL)
        {
            modelLightStruct_setLightKind(((BossDrakorState*)state)->lightObj, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(((BossDrakorState*)state)->lightObj, 0x40, 0, 0xff, 0xff);
            modelLightStruct_setSpecularColor(((BossDrakorState*)state)->lightObj, 0x40, 0, 0xff, 0xff);
            modelLightStruct_setupGlow(((BossDrakorState*)state)->lightObj, 0, 0x40, 0, 0x80, 0x5a, lbl_803E6564);
            modelLightStruct_setDistanceAttenuation(((BossDrakorState*)state)->lightObj, lbl_803E6544, lbl_803E6540);
            lightSetField4D((ModelLightStruct*)((BossDrakorState*)state)->lightObj, 0);
            modelLightStruct_setEnabled(((BossDrakorState*)state)->lightObj, 1, lbl_803E6520);
            modelLightStruct_setDiffuseTargetColor(((BossDrakorState*)state)->lightObj, 0x40, 0, 0x80, 0x40);
            modelLightStruct_setSpecularTargetColor((ModelLightStruct*)((BossDrakorState*)state)->lightObj, 0x40, 0,
                                                     0x80, 0x40);
            modelLightStruct_startColorFade(((BossDrakorState*)state)->lightObj, 2, 0x28);
            modelLightStruct_setAffectsAabbLightSelection((ModelLightStruct*)((BossDrakorState*)state)->lightObj, 1);
            modelLightStruct_setGlowProjectionRadius((ModelLightStruct*)((BossDrakorState*)state)->lightObj,
                                                      lbl_803E6550);
        }
    }
    moveResult = Obj_UpdateRomCurveFollowVelocityIndexed(
        (GameObject*)obj, (RomCurveWalker*)((char*)state + 0x28), ((BossDrakorState*)state)->curveIndex,
        lbl_803E6568, lbl_803E6520, 1, &((BossDrakorState*)state)->curveFollowState);
    if (((DrakorFlags*)((char*)state + 0x198))->b40)
    {
        player = (int)Obj_GetPlayerObject();
        if ((void*)player != NULL)
        {
            step = Obj_GetYawDeltaToObject((GameObject*)obj, (GameObject*)player, 0);
            ((GameObject*)obj)->anim.rotX +=
                (s16)(((s16)step < -0x200) ? -0x200 : (((s16)step > 0x200) ? 0x200 : (s16)step));
            step = ((GameObject*)obj)->anim.rotY;
            if (step != 0)
            {
                if (step < -0x100)
                {
                    step = -0x100;
                }
                else if (step > 0x100)
                {
                    step = 0x100;
                }
                ((GameObject*)obj)->anim.rotY -= (s16)step;
            }
            step = ((GameObject*)obj)->anim.rotZ;
            if (step != 0)
            {
                if (step < -0x100)
                {
                    step = -0x100;
                }
                else if (step > 0x100)
                {
                    step = 0x100;
                }
                ((GameObject*)obj)->anim.rotZ -= (s16)step;
            }
        }
    }
    else
    {
        Obj_SmoothTurnAnglesTowardVelocity((GameObject*)obj, (const Vec3f*)&((GameObject*)obj)->anim.velocityX, 0x2d,
                                           lbl_803E6548, lbl_803E656C);
    }
    if (moveResult != 0)
    {
        bossdrakor_handleActionEvent(obj, state, moveResult);
    }
    adv = ObjAnim_AdvanceCurrentMove(
        obj, (spd = PSVECMag(&((GameObject*)obj)->anim.velocityX) / ((BossDrakorState*)state)->moveSpeed) + lbl_803E6570,
        timeDelta, (ObjAnimEventList*)buf);
    if (adv != 0)
    {
        if (((BossDrakorState*)state)->moveState == 0)
        {
            ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
            ((DrakorFlags*)((char*)state + 0x198))->b04 = 0;
            ((DrakorFlags*)((char*)state + 0x198))->b08 = 0;
            if (!((DrakorFlags*)((char*)state + 0x198))->b40)
            {
                ((BossDrakorState*)state)->moveSpeed = lbl_803E6534;
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x28);
                moveId = 0x10;
            }
            else
            {
                moveId = bossdrakor_chooseNextMove((GameObject*)(obj), &((BossDrakorState*)state)->moveSpeed);
            }
            ObjAnim_SetCurrentMove(obj, moveId, lbl_803E6510, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, ((BossDrakorState*)state)->moveState, lbl_803E6510, 0);
        }
        if (arrayIndexOf(gBossDrakorTurnMoveStates, 5, ((BossDrakorState*)state)->moveState) != -1)
        {
            switch (((BossDrakorState*)state)->moveState)
            {
            case 0x12:
                ((DrakorFlags*)((char*)state + 0x198))->b40 = 0;
                ((BossDrakorState*)state)->moveState = 0;
                break;
            case 0x13:
                ((BossDrakorState*)state)->moveState = 0x16;
                ((BossDrakorState*)state)->moveSpeed = lbl_803E6534;
                break;
            case 0x16:
                ((BossDrakorState*)state)->moveState = 0x16;
                ((BossDrakorState*)state)->moveSpeed = lbl_803E6574;
                break;
            case 0x14:
                if (((DrakorFlags*)((char*)state + 0x198))->b08)
                {
                    ((BossDrakorState*)state)->moveState = 0;
                }
                else
                {
                    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, BOSSDRAKOR_HIT_VOLUME_SLOT, 1, 0);
                    ((BossDrakorState*)state)->moveState = 0x15;
                    ((BossDrakorState*)state)->moveSpeed = lbl_803E6574;
                }
                break;
            case 0x15:
                ((BossDrakorState*)state)->moveState = 0;
                ((BossDrakorState*)state)->moveSpeed = lbl_803E6514;
                ((DrakorFlags*)((char*)state + 0x198))->b04 = 1;
                break;
            }
        }
    }
    for (i = 0, p = buf; i < buf[0x1b]; i++)
    {
        switch (p[0x13])
        {
        case 0:
            Sfx_PlayFromObject(obj, SFXTRIG_mv_sliftloop11);
            break;
        case 7:
            Sfx_PlayFromObject(obj, SFXTRIG_mv_sliftloop11);
            break;
        }
        p++;
    }
    if (timerCountDown(&((BossDrakorState*)state)->attackTimer) != 0)
    {
        bossdrakor_spawnAttackObjects((GameObject*)(obj), state, ((BossDrakorState*)state)->attackType);
        if (((BossDrakorState*)state)->attackTimerDuration != lbl_803E6510)
        {
            s16toFloat(&((BossDrakorState*)state)->attackTimer,
                       ((BossDrakorState*)state)->attackTimerDuration);
        }
    }
    if ((((GameObject*)obj)->objectFlags & BOSSDRAKOR_OBJFLAG_RENDERED) == 0)
    {
        ((BossDrakorState*)state)->homePosX = ((GameObject*)obj)->anim.localPosX;
        ((BossDrakorState*)state)->homePosY = ((GameObject*)obj)->anim.localPosY - lbl_803E655C;
        ((BossDrakorState*)state)->homePosZ = ((GameObject*)obj)->anim.localPosZ;
    }
    objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (((DrakorFlags*)((char*)state + 0x198))->b20)
    {
        (*gGameUIInterface)->runAirMeter(((BossDrakorState*)state)->airMeterHandle);
    }
    t = lbl_803E6510;
    if (t != ((BossDrakorState*)state)->shakeAmount)
    {
        ((BossDrakorState*)state)->shakeVel = -(lbl_803E6578 * timeDelta - ((BossDrakorState*)state)->shakeVel);
        ((BossDrakorState*)state)->shakeAmount =
            ((BossDrakorState*)state)->shakeAmount + ((BossDrakorState*)state)->shakeVel;
        t = (((BossDrakorState*)state)->shakeAmount < t)
                ? t
                : ((((BossDrakorState*)state)->shakeAmount > lbl_803E6550) ? lbl_803E6550
                                                                           : ((BossDrakorState*)state)->shakeAmount);
        ((BossDrakorState*)state)->shakeAmount = t;
        shakeScaleZ = ((BossDrakorState*)state)->shakeScaleZ;
        shake = ((BossDrakorState*)state)->shakeAmount;
        tblRes = seqFn_800394a0();
        shakeX = (s16)(gBossDrakorDegToAngle * shake);
        shakeY = (s16)(gBossDrakorDegToAngle * (shake * shakeScaleZ));
        i = 0;
        tbl = tblRes;
        do
        {
            uvec = (s16*)objModelGetVecFn_800395d8((GameObject*)(obj), tbl[0]);
            if (uvec != NULL)
            {
                uvec[1] = shakeY;
                uvec[0] = shakeX;
                uvec[2] = 0;
            }
            tbl++;
            i++;
        } while (i < 5);
    }
    if (randFn_80080100(200) != 0 && ((DrakorFlags*)((char*)state + 0x198))->b40)
    {
    objAudioFn_80039270(obj, (void*)(state + 0x130), 0x2ff);
    }
    objAnimFn_80038f38((GameObject*)(obj), (char*)(state + 0x130));
    if (((DrakorFlags*)((char*)state + 0x198))->b04)
    {
        player = (int)Obj_GetPlayerObject();
        vec = objModelGetVecFn_800395d8((GameObject*)(obj), 0xe);
        if (vec != NULL)
        {
            f32 hxsq;
            f32 hzsq;
            ObjPath_GetPointWorldPosition((GameObject*)obj, 4, &hx, &hy, &hz, 0);
            PSVECSubtract(&((GameObject*)player)->anim.localPosX, &hx, &hx);
            hxsq = hx * hx;
            hzsq = hz * hz;
            d = (s16)getAngle(hy, sqrtf(hxsq + hzsq)) - (u16)vec[0];
            if (d > 0x8000)
            {
                d = (s16)((int)d - 0xffff);
            }
            if (d < -0x8000)
            {
                d += 0xffff;
            }
            step = (d < -(framesThisStep << 8)) ? -(framesThisStep << 8)
                                                : ((d > (framesThisStep << 8)) ? (framesThisStep << 8) : d);
            vec[0] += (s16)step;
        }
    }
    else
    {
        bossdrakor_updateHeadTracking((GameObject*)(obj), state);
    }
}

#pragma opt_propagation reset
#pragma opt_propagation off
void bossdrakor_updateHeadTracking(GameObject* obj, int state)
{
    s16* neck;
    s16* vecF;
    s16* vec10;
    int step;
    int step2;
    int v;
    s16 d;
    /* Partfx spawn parameter block (breath/steam emitted from the neck bone). */
    struct
    {
        u8 pad[6];
        s16 mode;
        f32 val;
        f32 vec[3];
    } prm;

    neck = objModelGetVecFn_800395d8(obj, 0xe);
    if (neck != NULL)
    {
        step = ((v = (s16)-neck[0]) < -(framesThisStep << 8))
                   ? -(framesThisStep << 8)
                   : ((v > (framesThisStep << 8)) ? (framesThisStep << 8) : v);
        neck[0] += (s16)step;
        PSVECSubtract(&((BossDrakorState*)state)->homePosX, &(obj)->anim.localPosX, prm.vec);
        prm.val = lbl_803E651C;
        if (fn_80080150(&((BossDrakorState*)state)->jawAnimAngle) != 0)
        {
            vecF = objModelGetVecFn_800395d8(obj, 0xf);
            if (vecF != NULL)
            {
                vec10 = objModelGetVecFn_800395d8(obj, 0x10);
                if (vec10 != NULL)
                {
                    d = (int)(((BossDrakorState*)state)->jawAnimAngle * lbl_803DC19A) - (u16)vecF[1];
                    if (d > 0x8000)
                    {
                        d = (s16)((int)d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    step2 = (d < -lbl_803DC198 * framesThisStep)
                                ? -lbl_803DC198 * framesThisStep
                                : ((d > lbl_803DC198 * framesThisStep) ? lbl_803DC198 * framesThisStep : d);
                    d = (s16)step2;
                    vecF[1] += d;
                    vec10[1] -= d;
                    if (timerCountDown(&((BossDrakorState*)state)->jawAnimAngle) != 0)
                    {
                        storeZeroToFloatParam(&((BossDrakorState*)state)->jawAnimAngle);
                    }
                    if (((BossDrakorState*)state)->jawAnimAngle > lbl_803E6520)
                    {
                        prm.mode = 45000;
                        (*gPartfxInterface)->spawnObject((void*)obj, BOSSDRAKOR_PARTFX, &prm, 1, -1, NULL);
                    }
                }
            }
        }
    }
}
#pragma opt_propagation reset

int bossdrakor_chooseNextMove(GameObject* obj, f32* speedOut)
{
    int state;
    int idx;
    int v;
    s16 d;
    u16 a;
    f32 dir[3];

    state = *(int*)&obj->extra;
    PSVECNormalize(&obj->anim.velocityX, dir);
    if (((BossDrakorState*)state)->moveState != 0)
    {
        *speedOut = lbl_803E6534;
        return ((BossDrakorState*)state)->moveState;
    }
    idx = 0;
    if (dir[1] > lbl_803E6538)
    {
        idx = 3;
    }
    else if (dir[1] < lbl_803E653C)
    {
        idx = 4;
    }
    else
    {
        a = (u16)(s16)getAngle(dir[0], dir[2]);
        d = obj->anim.rotX - a;
        if (d > 0x8000)
        {
            d = (s16)((int)d - 0xffff);
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        v = (d >= 0) ? d : -d;
        if (v > 0x2000)
        {
            v = (d >= 0) ? d : -d;
            if (v < 0x6000)
            {
                if (d > 0)
                {
                    idx = 1;
                }
                else
                {
                    idx = 2;
                }
            }
        }
    }
    v = gBossDrakorMoveStateTable[idx];
    *speedOut = gBossDrakorMoveSpeedTable[idx];
    return v;
}

void bossdrakor_spawnAttackObjects(GameObject* obj, int state, int action)
{
    int player;
    int hi;
    int lo;
    int missile;
    f32 spd;
    f32 prod;
    f32* mstate;
    ObjPlacement* setup;
    f32 target[3];
    f32 vecA[3];
    f32 vecB[3];
    f32 vecC[3];

    if (action < 0 || action >= 4)
    {
        return;
    }
    {
        switch (action)
        {
        case 3:
            break;
        case 1:
            player = (int)Obj_GetPlayerObject();
            if (((DrakorFlags*)((char*)state + 0x198))->b40)
            {
                if (Obj_IsLoadingLocked() != 0)
                {
                    setup = Obj_AllocObjectSetup(0x20, BOSSDRAKOR_CHILD_OBJ_MISSILE);
                    setup->posX = ((BossDrakorState*)state)->homePosX;
                    setup->posY = ((BossDrakorState*)state)->homePosY;
                    setup->posZ = ((BossDrakorState*)state)->homePosZ;
                    setup->color[0] = 1;
                    setup->color[1] = 1;
                    setup->color[2] = 0xff;
                    setup->color[3] = 0xff;
                    if ((void*)player != NULL)
                    {
                        missile = (int)loadObjectAtObject(obj, setup);
                        if ((void*)missile != NULL)
                        {
                            prod = lbl_803DC188 * Vec_distance(&(obj)->anim.worldPosX,
                                                               &((GameObject*)player)->anim.worldPosX);
                            target[0] = ((GameObject*)player)->anim.localPosX +
                                        (f32)(s32)randomGetRange(lo = (int)-prod, hi = (int)prod);
                            target[1] = ((GameObject*)player)->anim.localPosY + (f32)(s32)randomGetRange(lo, hi);
                            target[2] = ((GameObject*)player)->anim.localPosZ + (f32)(s32)randomGetRange(lo, hi);
                            PSVECSubtract(&((GameObject*)player)->anim.localPosX, &((BossDrakorState*)state)->homePosX,
                                          vecA);
                            PSVECSubtract(target, &((BossDrakorState*)state)->homePosX, vecB);
                            PSVECNormalize(vecA, vecA);
                            spd = ((BossDrakorState*)state)->missileLeadFactor *
                                      PSVECDotProduct(&((GameObject*)player)->anim.velocityX, vecA) +
                                  ((BossDrakorState*)state)->missileBaseSpeed;
                            PSVECScale(vecA, (f32*)((char*)missile + 0x24), spd);
                            mstate = *(f32**)((char*)missile + 0xb8);
                            PSVECScale(vecA, vecC, PSVECDotProduct(vecA, vecB));
                            PSVECSubtract(vecB, vecC, vecC);
                            PSVECNormalize(vecC, vecC);
                            PSVECScale(vecC, (f32*)((char*)missile + 0x24),
                                       ((BossDrakorState*)state)->missileBaseSpeed * lbl_803DC18C);
                            *mstate = spd;
                            drakormissile_startActiveLaunch((GameObject*)(missile));
                            storeZeroToFloatParam(&((BossDrakorState*)state)->jawAnimAngle);
                            s16toFloat(&((BossDrakorState*)state)->jawAnimAngle, 0x1e);
                            Sfx_PlayFromObject((int)obj, SFXTRIG__UNK);
                            Sfx_PlayFromObject((int)obj, SFXTRIG_cahit2_c);
                        }
                    }
                }
            }
            break;
        case 2:
            if (!((DrakorFlags*)((char*)state + 0x198))->b40)
            {
                if (Obj_IsLoadingLocked() != 0)
                {
                    setup = Obj_AllocObjectSetup(0x24, BOSSDRAKOR_CHILD_OBJ_ATTACK);
                    setup->color[0] = 2;
                    setup->color[1] = 1;
                    setup->color[2] = 0xff;
                    setup->color[3] = 0xff;
                    setup->posX = ((BossDrakorState*)state)->homePosX;
                    setup->posY = ((BossDrakorState*)state)->homePosY;
                    setup->posZ = ((BossDrakorState*)state)->homePosZ;
                    ((BossdrakorPlacement*)setup)->airMeterMax = 0x3c;
                    ((BossdrakorPlacement*)setup)->unk1C = lbl_803DC194;
                    ((BossdrakorPlacement*)setup)->curveStartIndex = lbl_803DC190;
                    loadObjectAtObject(obj, setup);
                    Sfx_PlayFromObject((int)obj, SFXTRIG__UNK);
                }
            }
            break;
        }
    }
}

void bossdrakor_free(GameObject* obj)
{
    int inner = *(int*)&(obj)->extra;
    ObjGroup_RemoveObject((int)obj, BOSSDRAKOR_OBJGROUP);
    if ((obj)->childObjs[0] != NULL)
    {
        ObjLink_DetachChild(obj, *(int*)&(obj)->childObjs[0]);
    }
    if (((BossDrakorState*)inner)->lightObj != NULL)
    {
        ModelLightStruct_free(((BossDrakorState*)inner)->lightObj);
    }
    Music_Trigger(MUSICTRIG_LVF_Tracking, 0);
    Music_Trigger(MUSICTRIG_citytombs, 0);
}

void bossdrakor_handleActionEvent(int obj, int state, int action)
{
    int* tbl = gBossDrakorMoveStateTable;
    f32 t;
    int found;
    if (action >= 26 || action <= -1)
    {
        return;
    }
    switch (action)
    {
    case 1:
        if (((DrakorFlags*)((char*)state + 0x198))->b40)
        {
            ((BossDrakorState*)state)->moveState = 0x12;
            if (((BossDrakorState*)state)->lightObj != NULL)
            {
                modelLightStruct_setEnabled(((BossDrakorState*)state)->lightObj, 0, lbl_803E651C);
            }
        }
        else
        {
            ((DrakorFlags*)((char*)state + 0x198))->b40 = 1;
            if (((BossDrakorState*)state)->lightObj != NULL)
            {
                modelLightStruct_setEnabled(((BossDrakorState*)state)->lightObj, 1, lbl_803E651C);
            }
        }
        break;
    case 2:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat(&((BossDrakorState*)state)->attackTimer, 0x1e);
        ((BossDrakorState*)state)->attackType = 2;
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6510;
        break;
    case 3:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat(&((BossDrakorState*)state)->attackTimer, 0x5a);
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6540;
        ((BossDrakorState*)state)->attackType = 1;
        ((BossDrakorState*)state)->missileBaseSpeed = *(f32*)((char*)tbl + 0x84);
        ((BossDrakorState*)state)->missileLeadFactor = *(f32*)((char*)tbl + 0x90);
        break;
    case 4:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat(&((BossDrakorState*)state)->attackTimer, 0x3c);
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6544;
        ((BossDrakorState*)state)->attackType = 1;
        ((BossDrakorState*)state)->missileBaseSpeed = *(f32*)((char*)tbl + 0x88);
        ((BossDrakorState*)state)->missileLeadFactor = *(f32*)((char*)tbl + 0x94);
        break;
    case 5:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat(&((BossDrakorState*)state)->attackTimer, 0x1e);
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6548;
        ((BossDrakorState*)state)->attackType = 1;
        ((BossDrakorState*)state)->missileBaseSpeed = *(f32*)((char*)tbl + 0x8c);
        ((BossDrakorState*)state)->missileLeadFactor = *(f32*)((char*)tbl + 0x98);
        break;
    case 6:
        t = lbl_803E6510;
        ((BossDrakorState*)state)->attackTimerDuration = t;
        ((BossDrakorState*)state)->attackTimer = t;
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        break;
    case 7:
        ((BossDrakorState*)state)->moveState = 0x13;
        ((BossDrakorState*)state)->moveSpeed = lbl_803E654C;
        ((DrakorFlags*)((char*)state + 0x198))->b08 = 0;
        break;
    case 25:
        ((BossDrakorState*)state)->moveState = 0x14;
        ((BossDrakorState*)state)->moveSpeed = lbl_803E654C;
        break;
    case 8:
        ((BossDrakorState*)state)->moveState = 0x11;
        break;
    case 9:
        ((BossDrakorState*)state)->moveState = 0;
        break;
    case 10:
    case 11:
    case 12:
        if (((BossDrakorState*)state)->airMeterHandle < (tbl + action)[0x1d])
        {
            ((BossDrakorState*)state)->curveFollowState = 1;
        }
        break;
    case 14:
    case 15:
    case 16:
    case 17:
    case 18:
    case 19:
        ((BossDrakorState*)state)->repeatCount++;
        if (((BossDrakorState*)state)->repeatCount > action - 0xd)
        {
            ((BossDrakorState*)state)->repeatCount = 0;
            ((BossDrakorState*)state)->curveFollowState = 1;
        }
        break;
    case 20:
    case 21:
    case 22:
    case 23:
        if (mainGetBit((s16)(action + 0xbe5)) != 0)
        {
            ((BossDrakorState*)state)->curveFollowState = 1;
        }
    case 24:
        found = ObjGroup_FindNearestObject(DRAKORHOVERPAD_OBJGROUP, obj, 0);
        if ((void*)found != NULL)
        {
            drakorhoverpad_resetPendingMotion((GameObject*)(found));
        }
        break;
    }
}

void bossdrakor_hitDetect(GameObject* obj)
{
    int inner = *(int*)&(obj)->extra;
    int setup = *(int*)&(obj)->anim.placementData;
    f32 hz;
    f32 hy;
    f32 hx;
    f32 shakeInit;
    int hit = ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &hx, &hy, &hz);
    if (hit == 0xf || hit == 0xe)
    {
        if (((DrakorFlags*)((char*)inner + 0x198))->b40)
        {
            ((BossDrakorState*)inner)->airMeterHandle -= 1;
            ((DrakorFlags*)((char*)inner + 0x198))->b08 = 1;
            if (((BossDrakorState*)inner)->airMeterHandle < 0)
            {
                mainSetBits(((BossdrakorPlacement*)setup)->defeatedGameBit, 1);
                spawnExplosionLegacy((int*)obj, lbl_803E6550, 1, 1, 1, 1, 1, 1, 1);
                Obj_RemoveFromUpdateList((u8*)obj);
                (*gMapEventInterface)->setMapAct(BOSSDRAKOR_MAP_ARENA, 3);
                mainSetBits(GAMEBIT_ITEM_WaterSpellStone2_Got, 1);
            }
            else
            {
                Obj_SpawnHitLightAndFade((GameObject*)obj, (const Vec3f*)&hx, lbl_803E6554);
            }
            if (((BossDrakorState*)inner)->hitSfxCooldown <= lbl_803E6510)
            {
                ((BossDrakorState*)inner)->hitSfxCooldown = lbl_803E6558;
                Sfx_PlayFromObject((int)obj, SFXTRIG__UNK_var);
            }
            if (((BossDrakorState*)inner)->hurtSfxCooldown <= lbl_803E6510)
            {
                ((BossDrakorState*)inner)->hurtSfxCooldown = lbl_803E6520;
                Sfx_PlayFromObject((int)obj, SFXTRIG_mpwru1);
            }
            shakeInit = lbl_803E6518;
            ((BossDrakorState*)inner)->shakeVel = shakeInit;
            ((BossDrakorState*)inner)->shakeAmount = shakeInit;
            ((BossDrakorState*)inner)->shakeScaleZ = (f32)(s32)randomGetRange(-0x32, 0x32) / lbl_803E655C;
        }
        else
        {
            if (((BossDrakorState*)inner)->hurtSfxCooldown < lbl_803E6510)
            {
                ((BossDrakorState*)inner)->hurtSfxCooldown = lbl_803E6520;
                Sfx_PlayFromObject((int)obj, SFXTRIG_sc_npu_216);
            }
        }
    }
    ((BossDrakorState*)inner)->hitSfxCooldown -= timeDelta;
    ((BossDrakorState*)inner)->hurtSfxCooldown -= timeDelta;
}

int bossdrakor_seqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int inner = *(int*)&(obj)->extra;
    int i;
    int target;
    int eventId;
    ((DrakorFlags*)((char*)inner + 0x198))->b10 = 1;
    if (((BossDrakorState*)inner)->textTimer > lbl_803E6510)
    {
        gameTextShow(0x569);
        ((BossDrakorState*)inner)->textTimer -= timeDelta;
        if (((BossDrakorState*)inner)->textTimer < lbl_803E6510)
        {
            ((BossDrakorState*)inner)->textTimer = lbl_803E6510;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        eventId = animUpdate->eventIds[i];
        switch (eventId)
        {
        case 6:
            target = ObjGroup_FindNearestObjectLegacy(DBHOLECONTROL1_OBJGROUP, obj, 0);
            if ((void*)target != NULL && (obj)->childCount != 0)
            {
                (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)&((GameObject*)target)->anim.dll) + 0x20)))(target, 2);
                ObjLink_DetachChild(obj, target);
            }
            break;
        case 7:
            target = ObjGroup_FindNearestObjectLegacy(DBHOLECONTROL1_OBJGROUP, obj, 0);
            if ((void*)target != NULL)
            {
                (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)&((GameObject*)target)->anim.dll) + 0x20)))(target, 0);
                ObjLink_AttachChildLegacy(obj, target, 1);
                ((BossDrakorState*)inner)->textTimer = lbl_803E6514;
            }
            break;
        case 9:
            ((DrakorFlags*)((char*)inner + 0x198))->b02 = 1;
            break;
        case 8:
            mainSetBits(GAMEBIT_DR_ObjGroups, 0);
            (*gMapEventInterface)->setObjGroupStatus(2, 0xf, 1);
            (*gMapEventInterface)->setObjGroupStatus(2, 0x10, 1);
            mainSetBits(GAMEBIT_DRArwingRelated0E7B, 0);
            warpToMap(0x79, 0);
            timeOfDayFn_80055000();
            break;
        }
    }
    if (((DrakorFlags*)((char*)inner + 0x198))->b02)
    {
        objParticleFn_80099d84(obj, lbl_803E6518, 6, lbl_803E651C, NULL);
    }
    return 0;
}
void bossdrakor_init(GameObject* obj, BossdrakorPlacement* init)
{
    int inner = *(int*)&(obj)->extra;
    f32 fz;
    if (init->curveStartIndex == 0)
    {
        init->curveStartIndex = 0xa;
    }
    if (init->airMeterMax <= 0)
    {
        init->airMeterMax = 0x1e;
    }
    ((BossDrakorState*)inner)->unk0C = 0;
    ((DrakorFlags*)((char*)inner + 0x198))->b80 = 0;
    ((BossDrakorState*)inner)->curveIndex = (f32)(u32)init->curveStartIndex;
    ((BossDrakorState*)inner)->airMeterHandle = init->airMeterMax;
    fz = lbl_803E6510;
    ((BossDrakorState*)inner)->attackTimerDuration = fz;
    ((BossDrakorState*)inner)->moveState = 0;
    ((BossDrakorState*)inner)->unk16C = -1;
    ((BossDrakorState*)inner)->attackType = 0;
    ((BossDrakorState*)inner)->moveSpeed = lbl_803E657C;
    ((DrakorFlags*)((char*)inner + 0x198))->b40 = 1;
    ((BossDrakorState*)inner)->shakeAmount = fz;
    ((BossDrakorState*)inner)->shakeVel = fz;
    ((BossDrakorState*)inner)->curveFollowState = 0;
    ((BossDrakorState*)inner)->textTimer = fz;
    ((DrakorFlags*)((char*)inner + 0x198))->b10 = 1;
    storeZeroToFloatParam(&((BossDrakorState*)inner)->attackTimer);
    ObjGroup_AddObject((int)obj, BOSSDRAKOR_OBJGROUP);
    storeZeroToFloatParam(&((BossDrakorState*)inner)->jawAnimAngle);
    (obj)->animEventCallback = bossdrakor_seqFn;
    Music_Trigger(MUSICTRIG_LVF_Tracking, 1);
    Music_Trigger(MUSICTRIG_citytombs, 1);
    ((BossDrakorState*)inner)->lightObj = 0;
}

void bossdrakor_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int*)&((GameObject*)p1)->extra;
    f32 pos2;
    f32 pos1;
    f32 pos0;
    ModelLightStruct* light;
    int val;
    objRenderModelAndHitVolumes((GameObject*)p1, lbl_803E651C);
    ObjPath_GetPointWorldPosition((GameObject*)p1, 0, &((BossDrakorState*)inner)->homePosX, &((BossDrakorState*)inner)->homePosY,
                                  &((BossDrakorState*)inner)->homePosZ, 0);
    if (((BossDrakorState*)inner)->lightObj != NULL)
    {
        ObjPath_GetPointWorldPosition((GameObject*)p1, 5, &pos0, &pos1, &pos2, 0);
        modelLightStruct_setPosition(((BossDrakorState*)inner)->lightObj, pos0, pos1, pos2);
        light = ((BossDrakorState*)inner)->lightObj;
        if (light->glowType != 0 && light->enabled != 0)
        {
            val = light->glowAlpha + light->glowAlphaStep;
            if (val < 0)
            {
                val = 0;
                light->glowAlphaStep = 0;
            }
            else if (val > 0xc)
            {
                val += randomGetRange(-0xc, 0xc);
                if (val > 0xff)
                {
                    val = 0xff;
                    ((BossDrakorState*)inner)->lightObj->glowAlphaStep = 0;
                }
            }
            ((BossDrakorState*)inner)->lightObj->glowAlpha = val;
        }
        light = ((BossDrakorState*)inner)->lightObj;
        if (light->glowType != 0 && light->enabled != 0)
        {
            queueGlowRender(light);
        }
    }
}

#pragma opt_common_subs reset

int gBossDrakorTurnMoveStates[32] = {
    18,         18,         19,         20,         21,         1000593162, 1000593162, 1000593162,
    1000593162, 1000593162, 1000593162, 1000593162, 1000593162, 1000593162, 1,          7,
    6,          7,          7,          1,          1,          3,          11,         1045220557,
    1045220557, 1045220557, 1034147594, 1031127695, 1031127695, 50,         100,        200,
};

int gBossDrakorMoveStateTable[5] = {1, 2, 3, 4, 5};
int gBossDrakorMoveSpeedTable[5] = {400, 400, 400, 600, 600};
