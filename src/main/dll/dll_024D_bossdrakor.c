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
#include "main/dll/DR/dll_80209FE0_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

void bossdrakor_release(void)
{
}

void bossdrakor_initialise(void)
{
}

typedef struct BossdrakorPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 unk19;
    s16 airMeterMax;
    s16 unk1C;
    s16 defeatedGameBit;
} BossdrakorPlacement;

typedef struct BossDrakorState
{
    f32 unk00;
    u8 pad04[8];
    int unk0C;
    f32 attackTimer;
    f32 attackTimerDuration;
    f32 unk18;
    f32 homePosX;
    f32 homePosY;
    f32 homePosZ;
    u8 pad28[0x68];
    f32 savedPosX;
    f32 savedPosY;
    f32 savedPosZ;
    u8 pad9C[0xc4];
    int lightObj; /* 0x160 */
    f32 unk164;
    int moveState; /* 0x168 */
    int unk16C;
    int airMeterHandle;
    int attackType;
    f32 shakeAmount;
    f32 shakeVel;
    f32 shakeScaleZ;
    f32 unk184;
    f32 unk188;
    f32 textTimer;
    u8 unk190;
    u8 pad191[3];
    int curveFollowState;
    u8 pad198[4];
    f32 hitSfxCooldown;
    f32 hurtSfxCooldown;
} BossDrakorState;

STATIC_ASSERT(sizeof(BossDrakorState) == 0x1a4);

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
    int* tbl;
    int shakeX;
    int shakeY;
    f32 shake;
    f32 shakeScaleZ;
    f32 v;
    f32 t;
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
        getEnvfxActImmediately(obj, obj, 0x144, 0);
        getEnvfxActImmediately(obj, obj, 0x10d, 0);
        getEnvfxActImmediately(obj, obj, 0x10e, 0);
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
        ((BossDrakorState*)state)->unk190 = 0;
        state2 = *(int*)&((GameObject*)obj)->extra;
        ((DrakorFlags*)((char*)state2 + 0x198))->b20 = 1;
        (*gGameUIInterface)->initAirMeter(((BossDrakorState*)state2)->airMeterHandle, 0x63e);
        (*gGameUIInterface)->runAirMeter(((BossDrakorState*)state2)->airMeterHandle);
        ((DrakorFlags*)((char*)state + 0x198))->b10 = 0;
        ((BossDrakorState*)state)->lightObj = objCreateLight(0, 1);
        if (*(void* *)&((BossDrakorState*)state)->lightObj != NULL)
        {
            modelLightStruct_setLightKind(((BossDrakorState*)state)->lightObj, 2);
            modelLightStruct_setDiffuseColor(((BossDrakorState*)state)->lightObj, 0x40, 0, 0xff, 0xff);
            modelLightStruct_setSpecularColor(((BossDrakorState*)state)->lightObj, 0x40, 0, 0xff, 0xff);
            modelLightStruct_setupGlow(((BossDrakorState*)state)->lightObj, 0, 0x40, 0, 0x80, 0x5a, lbl_803E6564);
            modelLightStruct_setDistanceAttenuation(((BossDrakorState*)state)->lightObj, lbl_803E6544, lbl_803E6540);
            lightSetField4D(((BossDrakorState*)state)->lightObj, 0);
            modelLightStruct_setEnabled(*(void* *)&((BossDrakorState*)state)->lightObj, 1, lbl_803E6520);
            modelLightStruct_setDiffuseTargetColor(((BossDrakorState*)state)->lightObj, 0x40, 0, 0x80, 0x40);
            modelLightStruct_setSpecularTargetColor(((BossDrakorState*)state)->lightObj, 0x40, 0, 0x80, 0x40);
            modelLightStruct_startColorFade(((BossDrakorState*)state)->lightObj, 2, 0x28);
            modelLightStruct_setAffectsAabbLightSelection(((BossDrakorState*)state)->lightObj, 1);
            modelLightStruct_setGlowProjectionRadius(((BossDrakorState*)state)->lightObj, lbl_803E6550);
        }
    }
    moveResult = Obj_UpdateRomCurveFollowVelocityIndexed(((BossDrakorState*)state)->unk00, lbl_803E6568, lbl_803E6520, obj,
                                                         (void*)((char*)state + 0x28), 1,
                                                         &((BossDrakorState*)state)->curveFollowState);
    if (((DrakorFlags*)((char*)state + 0x198))->b40)
    {
        player = (int)Obj_GetPlayerObject();
        if ((void*)player != NULL)
        {
            d = Obj_GetYawDeltaToObject(obj, player, 0);
            if (d < -0x200)
            {
                d = -0x200;
            }
            else if (d > 0x200)
            {
                d = 0x200;
            }
            ((GameObject*)obj)->anim.rotX += d;
            d = ((GameObject*)obj)->anim.rotY;
            if (d != 0)
            {
                if (d < -0x100)
                {
                    d = -0x100;
                }
                else if (d > 0x100)
                {
                    d = 0x100;
                }
                ((GameObject*)obj)->anim.rotY -= d;
            }
            d = ((GameObject*)obj)->anim.rotZ;
            if (d != 0)
            {
                if (d < -0x100)
                {
                    d = -0x100;
                }
                else if (d > 0x100)
                {
                    d = 0x100;
                }
                ((GameObject*)obj)->anim.rotZ -= d;
            }
        }
    }
    else
    {
        Obj_SmoothTurnAnglesTowardVelocity(obj, &((GameObject*)obj)->anim.velocityX, 0x2d, lbl_803E6548,
                                           lbl_803E656C);
    }
    if (moveResult != 0)
    {
        bossdrakor_handleActionEvent(obj, state, moveResult);
    }
    adv = ((int (*)(f32, int, f32, void*))ObjAnim_AdvanceCurrentMove)(
        lbl_803E6570 + PSVECMag(&((GameObject*)obj)->anim.velocityX) / ((BossDrakorState*)state)->unk164, obj,
        timeDelta, buf);
    if (adv != 0)
    {
        if (((BossDrakorState*)state)->moveState == 0)
        {
            ObjHits_ClearHitVolumes(obj);
            ((DrakorFlags*)((char*)state + 0x198))->b04 = 0;
            ((DrakorFlags*)((char*)state + 0x198))->b08 = 0;
            if (!((DrakorFlags*)((char*)state + 0x198))->b40)
            {
                ((BossDrakorState*)state)->unk164 = lbl_803E6534;
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x28);
                moveId = 0x10;
            }
            else
            {
                moveId = bossdrakor_chooseNextMove(obj, &((BossDrakorState*)state)->unk164);
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
                ((BossDrakorState*)state)->unk164 = lbl_803E6534;
                break;
            case 0x16:
                ((BossDrakorState*)state)->moveState = 0x16;
                ((BossDrakorState*)state)->unk164 = lbl_803E6574;
                break;
            case 0x14:
                if (((DrakorFlags*)((char*)state + 0x198))->b08)
                {
                    ((BossDrakorState*)state)->moveState = 0;
                }
                else
                {
                    ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
                    ((BossDrakorState*)state)->moveState = 0x15;
                    ((BossDrakorState*)state)->unk164 = lbl_803E6574;
                }
                break;
            case 0x15:
                ((BossDrakorState*)state)->moveState = 0;
                ((BossDrakorState*)state)->unk164 = lbl_803E6514;
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
            Sfx_PlayFromObject(obj, 0x481);
            break;
        case 7:
            Sfx_PlayFromObject(obj, 0x481);
            break;
        }
        p++;
    }
    if (timerCountDown(&((BossDrakorState*)state)->attackTimer) != 0)
    {
        bossdrakor_spawnAttackObjects(obj, state, ((BossDrakorState*)state)->attackType);
        if (((BossDrakorState*)state)->attackTimerDuration != lbl_803E6510)
        {
            s16toFloat((void*)&((BossDrakorState*)state)->attackTimer,
                       (int)((BossDrakorState*)state)->attackTimerDuration);
        }
    }
    if ((((GameObject*)obj)->objectFlags & 0x800) == 0)
    {
        ((BossDrakorState*)state)->homePosX = ((GameObject*)obj)->anim.localPosX;
        ((BossDrakorState*)state)->homePosY = ((GameObject*)obj)->anim.localPosY - lbl_803E655C;
        ((BossDrakorState*)state)->homePosZ = ((GameObject*)obj)->anim.localPosZ;
    }
    objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (((DrakorFlags*)((char*)state + 0x198))->b20)
    {
        (*gGameUIInterface)->runAirMeter(((BossDrakorState*)state)->airMeterHandle);
    }
    t = lbl_803E6510;
    if (t != ((BossDrakorState*)state)->shakeAmount)
    {
        ((BossDrakorState*)state)->shakeVel = -(lbl_803E6578 * timeDelta - ((BossDrakorState*)state)->shakeVel);
        ((BossDrakorState*)state)->shakeAmount = ((BossDrakorState*)state)->shakeAmount + ((BossDrakorState*)state)->shakeVel;
        v = ((BossDrakorState*)state)->shakeAmount;
        t = (v < t) ? t : ((v > lbl_803E6550) ? lbl_803E6550 : v);
        ((BossDrakorState*)state)->shakeAmount = t;
        shakeScaleZ = ((BossDrakorState*)state)->shakeScaleZ;
        shake = ((BossDrakorState*)state)->shakeAmount;
        tbl = seqFn_800394a0();
        shakeX = (int)(gBossDrakorDegToAngle * shake);
        shakeY = (int)(gBossDrakorDegToAngle * (shake * shakeScaleZ));
        i = 0;
        do
        {
            uvec = (s16*)objModelGetVecFn_800395d8(obj, tbl[0]);
            if (uvec != NULL)
            {
                uvec[1] = shakeY;
                uvec[0] = shakeX;
                uvec[2] = 0;
            }
            tbl++;
            i++;
        }
        while (i < 5);
    }
    if (randFn_80080100(200) != 0 && ((DrakorFlags*)((char*)state + 0x198))->b40)
    {
        objAudioFn_80039270(obj, state + 0x130, 0x2ff);
    }
    objAnimFn_80038f38(obj, state + 0x130);
    if (((DrakorFlags*)((char*)state + 0x198))->b04)
    {
        player = (int)Obj_GetPlayerObject();
        vec = objModelGetVecFn_800395d8(obj, 0xe);
        if (vec != NULL)
        {
            f32 hxsq;
            f32 hzsq;
            ObjPath_GetPointWorldPosition(obj, 4, &hx, &hy, &hz, 0);
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
            step = (d < -(framesThisStep << 8))
                       ? -(framesThisStep << 8)
                       : ((d > (framesThisStep << 8)) ? (framesThisStep << 8) : d);
            vec[0] += (s16)step;
        }
    }
    else
    {
        bossdrakor_updateHeadTracking(obj, state);
    }
}

#pragma opt_propagation reset
#pragma opt_propagation off
void bossdrakor_updateHeadTracking(int obj, int state)
{
    s16* neck;
    s16* vecF;
    s16* vec10;
    int step;
    int step2;
    int v;
    s16 d;
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
        v = (s16)-neck[0];
        step = (v < -(framesThisStep << 8))
                   ? -(framesThisStep << 8)
                   : ((v > (framesThisStep << 8)) ? (framesThisStep << 8) : v);
        neck[0] += (s16)step;
        PSVECSubtract(&((BossDrakorState*)state)->homePosX, &((GameObject*)obj)->anim.localPosX, prm.vec);
        prm.val = lbl_803E651C;
        if (fn_80080150((int)((char*)state + 0x18)) != 0)
        {
            vecF = objModelGetVecFn_800395d8(obj, 0xf);
            if (vecF != NULL)
            {
                vec10 = objModelGetVecFn_800395d8(obj, 0x10);
                if (vec10 != NULL)
                {
                    d = (int)(((BossDrakorState*)state)->unk18 * lbl_803DC19A) - (u16)vecF[1];
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
                    if (timerCountDown(&((BossDrakorState*)state)->unk18) != 0)
                    {
                        storeZeroToFloatParam(&((BossDrakorState*)state)->unk18);
                    }
                    if (((BossDrakorState*)state)->unk18 > lbl_803E6520)
                    {
                        prm.mode = 45000;
                        (*gPartfxInterface)->spawnObject(
                            (void*)obj, 0x7ad, &prm, 1, -1, NULL);
                    }
                }
            }
        }
    }
}
#pragma opt_propagation reset

int bossdrakor_chooseNextMove(int obj, f32* speedOut)
{
    int state;
    int idx;
    int v;
    s16 d;
    u16 a;
    f32 dir[3];

    state = *(int*)&((GameObject*)obj)->extra;
    PSVECNormalize(&((GameObject*)obj)->anim.velocityX, dir);
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
        d = ((GameObject*)obj)->anim.rotX - a;
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

void bossdrakor_spawnAttackObjects(int obj, int state, int action)
{
    int player;
    int hi;
    int lo;
    int missile;
    f32 spd;
    f32 prod;
    f32* mstate;
    u8* setup;
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
                    setup = Obj_AllocObjectSetup(0x20, 0x70f);
                    ((ObjPlacement*)setup)->posX = ((BossDrakorState*)state)->homePosX;
                    ((ObjPlacement*)setup)->posY = ((BossDrakorState*)state)->homePosY;
                    ((ObjPlacement*)setup)->posZ = ((BossDrakorState*)state)->homePosZ;
                    setup[4] = 1;
                    setup[5] = 1;
                    setup[6] = 0xff;
                    setup[7] = 0xff;
                    if ((void*)player != NULL)
                    {
                        missile = loadObjectAtObject(obj, setup);
                        if ((void*)missile != NULL)
                        {
                            prod = lbl_803DC188 * Vec_distance((int*)&((GameObject*)obj)->anim.worldPosX,
                                                               (int*)&((GameObject*)player)->anim.worldPosX);
                            target[0] = ((GameObject*)player)->anim.localPosX + (f32)(s32)randomGetRange(lo = (int)-prod, hi = (int)prod);
                            target[1] = ((GameObject*)player)->anim.localPosY + (f32)(s32)randomGetRange(lo, hi);
                            target[2] = ((GameObject*)player)->anim.localPosZ + (f32)(s32)randomGetRange(lo, hi);
                            PSVECSubtract(&((GameObject*)player)->anim.localPosX, &((BossDrakorState*)state)->homePosX,
                                          vecA);
                            PSVECSubtract(target, &((BossDrakorState*)state)->homePosX, vecB);
                            PSVECNormalize(vecA, vecA);
                            spd = ((BossDrakorState*)state)->unk188 * PSVECDotProduct(
                                &((GameObject*)player)->anim.velocityX, vecA) + ((BossDrakorState*)state)->unk184;
                            PSVECScale(vecA, (f32*)((char*)missile + 0x24), spd);
                            mstate = *(f32**)((char*)missile + 0xb8);
                            PSVECScale(vecA, vecC, PSVECDotProduct(vecA, vecB));
                            PSVECSubtract(vecB, vecC, vecC);
                            PSVECNormalize(vecC, vecC);
                            PSVECScale(vecC, (f32*)((char*)missile + 0x24),
                                       ((BossDrakorState*)state)->unk184 * lbl_803DC18C);
                            *mstate = spd;
                            drakormissile_startActiveLaunch(missile);
                            storeZeroToFloatParam(&((BossDrakorState*)state)->unk18);
                            s16toFloat((void*)&((BossDrakorState*)state)->unk18, 0x1e);
                            Sfx_PlayFromObject(obj, 0x477);
                            Sfx_PlayFromObject(obj, 0x3c8);
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
                    setup = Obj_AllocObjectSetup(0x24, 0x709);
                    setup[4] = 2;
                    setup[5] = 1;
                    setup[6] = 0xff;
                    setup[7] = 0xff;
                    ((ObjPlacement*)setup)->posX = ((BossDrakorState*)state)->homePosX;
                    ((ObjPlacement*)setup)->posY = ((BossDrakorState*)state)->homePosY;
                    ((ObjPlacement*)setup)->posZ = ((BossDrakorState*)state)->homePosZ;
                    *(s16*)(setup + 0x1a) = 0x3c;
                    *(s16*)(setup + 0x1c) = lbl_803DC194;
                    *(s8*)(setup + 0x19) = lbl_803DC190;
                    loadObjectAtObject(obj, setup);
                    Sfx_PlayFromObject(obj, 0x477);
                }
            }
            break;
        }
    }
}

void bossdrakor_free(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 0x45);
    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        ObjLink_DetachChild(obj, *(int*)&((GameObject*)obj)->childObjs[0]);
    }
    if (*(void* *)&((BossDrakorState*)inner)->lightObj != NULL)
    {
        ModelLightStruct_free(((BossDrakorState*)inner)->lightObj);
    }
    Music_Trigger(0x26, 0);
    Music_Trigger(0x96, 0);
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
            if (*(void* *)&((BossDrakorState*)state)->lightObj != NULL)
            {
                modelLightStruct_setEnabled(*(void* *)&((BossDrakorState*)state)->lightObj, 0, lbl_803E651C);
            }
        }
        else
        {
            ((DrakorFlags*)((char*)state + 0x198))->b40 = 1;
            if (*(void* *)&((BossDrakorState*)state)->lightObj != NULL)
            {
                modelLightStruct_setEnabled(*(void* *)&((BossDrakorState*)state)->lightObj, 1, lbl_803E651C);
            }
        }
        break;
    case 2:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat((void*)&((BossDrakorState*)state)->attackTimer, 0x1e);
        ((BossDrakorState*)state)->attackType = 2;
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6510;
        break;
    case 3:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat((void*)&((BossDrakorState*)state)->attackTimer, 0x5a);
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6540;
        ((BossDrakorState*)state)->attackType = 1;
        ((BossDrakorState*)state)->unk184 = *(f32*)((char*)tbl + 0x84);
        ((BossDrakorState*)state)->unk188 = *(f32*)((char*)tbl + 0x90);
        break;
    case 4:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat((void*)&((BossDrakorState*)state)->attackTimer, 0x3c);
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6544;
        ((BossDrakorState*)state)->attackType = 1;
        ((BossDrakorState*)state)->unk184 = *(f32*)((char*)tbl + 0x88);
        ((BossDrakorState*)state)->unk188 = *(f32*)((char*)tbl + 0x94);
        break;
    case 5:
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        s16toFloat((void*)&((BossDrakorState*)state)->attackTimer, 0x1e);
        ((BossDrakorState*)state)->attackTimerDuration = lbl_803E6548;
        ((BossDrakorState*)state)->attackType = 1;
        ((BossDrakorState*)state)->unk184 = *(f32*)((char*)tbl + 0x8c);
        ((BossDrakorState*)state)->unk188 = *(f32*)((char*)tbl + 0x98);
        break;
    case 6:
        t = lbl_803E6510;
        ((BossDrakorState*)state)->attackTimerDuration = t;
        ((BossDrakorState*)state)->attackTimer = t;
        storeZeroToFloatParam(&((BossDrakorState*)state)->attackTimer);
        break;
    case 7:
        ((BossDrakorState*)state)->moveState = 0x13;
        ((BossDrakorState*)state)->unk164 = lbl_803E654C;
        ((DrakorFlags*)((char*)state + 0x198))->b08 = 0;
        break;
    case 25:
        ((BossDrakorState*)state)->moveState = 0x14;
        ((BossDrakorState*)state)->unk164 = lbl_803E654C;
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
        ((BossDrakorState*)state)->unk190++;
        if (((BossDrakorState*)state)->unk190 > action - 0xd)
        {
            ((BossDrakorState*)state)->unk190 = 0;
            ((BossDrakorState*)state)->curveFollowState = 1;
        }
        break;
    case 20:
    case 21:
    case 22:
    case 23:
        if (GameBit_Get((s16)(action + 0xbe5)) != 0)
        {
            ((BossDrakorState*)state)->curveFollowState = 1;
        }
    case 24:
        found = ObjGroup_FindNearestObject(0x46, obj, 0);
        if ((void*)found != NULL)
        {
            drakorhoverpad_resetPendingMotion(found);
        }
        break;
    }
}

void bossdrakor_hitDetect(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
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
                GameBit_Set(((BossdrakorPlacement*)setup)->defeatedGameBit, 1);
                spawnExplosion((int*)obj, lbl_803E6550, 1, 1, 1, 1, 1, 1, 1);
                Obj_RemoveFromUpdateList((int*)obj);
                (*gMapEventInterface)->setMapAct(0x1d, 3);
                GameBit_Set(0x83c, 1);
            }
            else
            {
                Obj_SpawnHitLightAndFade(obj, &hx, lbl_803E6554);
            }
            if (((BossDrakorState*)inner)->hitSfxCooldown <= lbl_803E6510)
            {
                ((BossDrakorState*)inner)->hitSfxCooldown = lbl_803E6558;
                Sfx_PlayFromObject(obj, 0x478);
            }
            if (((BossDrakorState*)inner)->hurtSfxCooldown <= lbl_803E6510)
            {
                ((BossDrakorState*)inner)->hurtSfxCooldown = lbl_803E6520;
                Sfx_PlayFromObject(obj, 0x4af);
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
                Sfx_PlayFromObject(obj, 0x4b0);
            }
        }
    }
    ((BossDrakorState*)inner)->hitSfxCooldown -= timeDelta;
    ((BossDrakorState*)inner)->hurtSfxCooldown -= timeDelta;
}

int bossdrakor_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
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
            target = ObjGroup_FindNearestObject(0x1e, obj, 0);
            if ((void*)target != NULL && ((GameObject*)obj)->childCount != 0)
            {
                (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)&((GameObject*)target)->anim.dll) + 0x20)))(target, 2);
                ObjLink_DetachChild(obj, target);
            }
            break;
        case 7:
            target = ObjGroup_FindNearestObject(0x1e, obj, 0);
            if ((void*)target != NULL)
            {
                (*(void (*)(int, int))(*(int*)(*(int*)(*(int*)&((GameObject*)target)->anim.dll) + 0x20)))(target, 0);
                ObjLink_AttachChild(obj, target, 1);
                ((BossDrakorState*)inner)->textTimer = lbl_803E6514;
            }
            break;
        case 9:
            ((DrakorFlags*)((char*)inner + 0x198))->b02 = 1;
            break;
        case 8:
            GameBit_Set(0x5db, 0);
            (*gMapEventInterface)->setObjGroupStatus(2, 0xf, 1);
            (*gMapEventInterface)->setObjGroupStatus(2, 0x10, 1);
            GameBit_Set(0xe7b, 0);
            warpToMap(0x79, 0);
            timeOfDayFn_80055000();
            break;
        }
    }
    if (((DrakorFlags*)((char*)inner + 0x198))->b02)
    {
        objParticleFn_80099d84(obj, lbl_803E6518, 6, lbl_803E651C, 0);
    }
    return 0;
}

void bossdrakor_init(int obj, BossdrakorPlacement* init)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 fz;
    if (init->unk19 == 0)
    {
        init->unk19 = 0xa;
    }
    if (init->airMeterMax <= 0)
    {
        init->airMeterMax = 0x1e;
    }
    ((BossDrakorState*)inner)->unk0C = 0;
    ((DrakorFlags*)((char*)inner + 0x198))->b80 = 0;
    ((BossDrakorState*)inner)->unk00 = (f32)(u32)init->unk19;
    ((BossDrakorState*)inner)->airMeterHandle = init->airMeterMax;
    fz = lbl_803E6510;
    ((BossDrakorState*)inner)->attackTimerDuration = fz;
    ((BossDrakorState*)inner)->moveState = 0;
    ((BossDrakorState*)inner)->unk16C = -1;
    ((BossDrakorState*)inner)->attackType = 0;
    ((BossDrakorState*)inner)->unk164 = lbl_803E657C;
    ((DrakorFlags*)((char*)inner + 0x198))->b40 = 1;
    ((BossDrakorState*)inner)->shakeAmount = fz;
    ((BossDrakorState*)inner)->shakeVel = fz;
    ((BossDrakorState*)inner)->curveFollowState = 0;
    ((BossDrakorState*)inner)->textTimer = fz;
    ((DrakorFlags*)((char*)inner + 0x198))->b10 = 1;
    storeZeroToFloatParam(&((BossDrakorState*)inner)->attackTimer);
    ObjGroup_AddObject(obj, 0x45);
    storeZeroToFloatParam(&((BossDrakorState*)inner)->unk18);
    ((GameObject*)obj)->animEventCallback = bossdrakor_animEventCallback;
    Music_Trigger(0x26, 1);
    Music_Trigger(0x96, 1);
    ((BossDrakorState*)inner)->lightObj = 0;
}

void bossdrakor_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int*)&((GameObject*)p1)->extra;
    f32 pos2;
    f32 pos1;
    f32 pos0;
    int light;
    int val;
    objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E651C);
    ObjPath_GetPointWorldPosition(p1, 0, (char*)inner + 0x1c, (char*)inner + 0x20, (char*)inner + 0x24, 0);
    if (*(void* *)&((BossDrakorState*)inner)->lightObj != NULL)
    {
        ObjPath_GetPointWorldPosition(p1, 5, &pos0, &pos1, &pos2, 0);
        modelLightStruct_setPosition(((BossDrakorState*)inner)->lightObj, pos0, pos1, pos2);
        light = ((BossDrakorState*)inner)->lightObj;
        if (*(u8*)((char*)light + 0x2f8) != 0 && *(u8*)((char*)light + 0x4c) != 0)
        {
            val = *(u8*)((char*)light + 0x2f9) + (s8) * (u8*)((char*)light + 0x2fa);
            if (val < 0)
            {
                val = 0;
                *(u8*)((char*)light + 0x2fa) = 0;
            }
            else if (val > 0xc)
            {
                val += randomGetRange(-0xc, 0xc);
                if (val > 0xff)
                {
                    val = 0xff;
                    *(u8*)((char*)((BossDrakorState*)inner)->lightObj + 0x2fa) = 0;
                }
            }
            *(u8*)((char*)((BossDrakorState*)inner)->lightObj + 0x2f9) = val;
        }
        light = ((BossDrakorState*)inner)->lightObj;
        if (*(u8*)((char*)light + 0x2f8) != 0 && *(u8*)((char*)light + 0x4c) != 0)
        {
            queueGlowRender(light);
        }
    }
}

#pragma opt_common_subs reset
