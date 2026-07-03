/*
 * drhightop / SnowBike (DLL 0x255) - the snowbike "Hightop" ride object.
 *
 * Implements the per-frame logic of the snowbike vehicle: route following
 * along a checkpoint path (fn_801EAE4C / gCheckpointInterface), the air /
 * fuel meter and its UI + shutdown sequence (fn_801EB0D4), spawn / reset
 * latching (fn_801EB334), the animation-event/sequence callback that seeds
 * the launch impulse from per-step velocity (SnowBike_animEventCallback),
 * collision response and impact particle bursts (fn_801EB634), steering /
 * pitch-roll integration with rumble + camera shake (fn_801EB940), and the
 * exhaust/contrail particle drivers blended toward per-state targets
 * (fn_801EBD60). State lives in SnowBikeState (BWalphaanim.h); flags428 is
 * a bitfield overlay byte read via the Hightop* flag structs below.
 * Entry points are dispatched from dll_0255_snowbike.c.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/checkpoint_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/BW/BWalphaanim.h"
#include "main/dll/DR/DRcloudcage.h"
#include "main/dll/path_control_interface.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"


extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 PSVECMag(void* vec);
extern void PSVECScale(f32* dst, f32* src, f32 s);
extern void PSVECNormalize(void* src, void* dst);
extern f32 PSVECDotProduct(void* a, void* b);
extern int randomGetRange(int lo, int hi);
extern void setMotionBlur(u8 enabled, f32 amount);




extern f32 sqrtf(f32);
extern void fn_8009A8C8();
extern int arrayIndexOf(int* arr, int count, int target);
extern void SnowBike_func15();
extern u8 framesThisStep;
extern f32 oneOverTimeDelta;
extern f32 timeDelta;
extern char lbl_803AD088[];
extern int gDrHighTopHitObjectKinds[];
extern int lbl_803DC0BC;
extern f32 lbl_803DC0C8;
extern int lbl_803DC0CC;
extern int lbl_803DC0D0;
extern int lbl_803DC0D4;
extern f32 lbl_803DC0D8;
extern s16 lbl_803DC0DC;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF4;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B2C;
extern f32 lbl_803E5B34;
extern f32 lbl_803E5B40;
extern f32 lbl_803E5B68;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B7C;
extern f32 lbl_803E5B80;
extern f32 lbl_803E5B84;
extern f32 lbl_803E5B88;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5B9C;
extern f32 lbl_803E5BA0;
extern f32 lbl_803E5BA8;
extern f32 lbl_803E5BAC;
extern f32 lbl_803E5BB0;
extern f32 lbl_803E5BB4;
extern f32 lbl_803E5BB8;
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC0;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5BC8;
extern f32 lbl_803E5BCC;
extern f32 gDrHighTopPi;
extern f32 lbl_803E5BD4;
extern f32 lbl_803E5BD8;
extern f32 lbl_803E5BDC;
extern f32 lbl_803E5BE0;
extern f32 lbl_803E5BE4;
extern f32 lbl_803E5BE8;
extern f32 lbl_803E5BEC;
extern f32 lbl_803E5BF0;
extern f32 lbl_803E5BF4;
extern f32 lbl_803E5BF8;
extern f32 lbl_803E5BFC;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C04;
extern f32 lbl_803E5C08;
extern f32 lbl_803E5C0C;
extern f32 lbl_803E5C10;
extern f32 lbl_803E5C14;

typedef struct HightopFlags3
{
    u8 hi : 4;
    u8 active : 1;
    u8 lo : 3;
} HightopFlags3;

void fn_801EAE4C(short* obj, int stateRaw)
{
    f32 tickDir;
    u32 bitVal;
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    s16 angDelta;
    u32 absDelta;
    u16 uRet;
    s8 ch;

    if ((u32)(st->flags428 >> 3 & 1) == 0)
    {
        st->checkpointIndexA = 0xffffffff;
        st->checkpointIndexB = 0xffffffff;
        st->checkpointIndexC = 0xffffffff;
        st->unk044 = 0;
        lbl_803DC0BC = -1;
        bitVal = GameBit_Get((int)*(short*)st->unk060);
        if (bitVal != 0)
        {
            ((HightopFlags3*)&st->flags428)->active = 1;
        }
        if ((u32)(st->flags428 >> 3 & 1) != 0)
        {
            if ((u32)(st->flags428 >> 1 & 1) != 0)
            {
                SnowBike_func15(obj);
            }
            else
            {
                (*gCheckpointInterface)
                    ->findRouteForObject((GameObject*)obj, (CheckpointRouteState*)(stateRaw + 0x28),
                                         st->unk05C);
            }
            (*gCheckpointInterface)->rewindRoute((CheckpointRouteState*)(stateRaw + 0x28));
        }
    }
    else
    {
        if ((u32)(st->flags428 >> 1 & 1) == 0)
        {
            uRet = (*gCheckpointInterface)
                       ->getRouteHeading((GameObject*)obj, (CheckpointRouteState*)(stateRaw + 0x28));
            angDelta = *obj - uRet;
            if (0x8000 < angDelta)
            {
                angDelta = angDelta - 0xffff;
            }
            if (angDelta < -0x8000)
            {
                angDelta = angDelta + 0xffff;
            }
            absDelta = ((int)angDelta >= 0) ? angDelta : -angDelta;
            /* Branchless "absDelta <= lbl_803DC0DC": the sign bit (>>0x1f) of
             * ((x>>1) - (x & absDelta)), x = absDelta ^ lbl_803DC0DC, is 0
             * exactly when absDelta does not exceed the threshold. Advance the
             * path progress forward while within tolerance, else back it off. */
            if ((int)((u32)(((int)(absDelta ^ lbl_803DC0DC) >> 1) - ((absDelta ^ lbl_803DC0DC) & absDelta)) >> 0x1f) ==
                0)
            {
                tickDir = timeDelta;
            }
            else
            {
                tickDir = -timeDelta;
            }
            st->pathProgress = st->pathProgress + tickDir;
            tickDir = st->pathProgress;
            st->pathProgress =
                (tickDir < lbl_803E5AE8)
                    ? lbl_803E5AE8
                    : ((tickDir > lbl_803E5B68) ? lbl_803E5B68 : tickDir);
            if (st->pathProgress > lbl_803E5B7C)
            {
                gameTextShow(0x475);
            }
            (*gCheckpointInterface)->queueRouteRankItem((CheckpointRankItem*)(stateRaw + 0x28));
            st->unk422 =
                (s8)(*gCheckpointInterface)->getRouteRank((CheckpointRankItem*)(stateRaw + 0x28));
            ch = st->unk422;
            if ((ch == 1) && (lbl_803DC0BC == -1))
            {
                lbl_803DC0BC = -1;
            }
            else
            {
                lbl_803DC0BC = ch;
                *(int*)(lbl_803AD088 + 0x1c) = st->unk044;
                *(f32*)(lbl_803AD088 + 0xc) = st->unk034;
            }
        }
        bitVal = GameBit_Get((int)*(short*)(st->unk060 + 2));
        if (bitVal != 0)
        {
            ((HightopFlags3*)&st->flags428)->active = 0;
        }
    }
}

void fn_801EB0D4(u32 obj, int stateRaw)
{
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    f32 rate;
    f32 lim;
    f32 td;

    if ((u32)(st->flags428 >> 5 & 1) != 0)
    {
        if (st->airMeterCurrent >= lbl_803E5AE8)
        {
            td = timeDelta;
            st->airMeterCurrent -=
                td * lbl_803DC0D8 + (f32)(s32)(st->airDrainRate *
                    (td * PSVECMag(&st->localVelX)));
            lim = lbl_803E5AE8;
            if (lim != st->airMeterRefillTimer)
            {
                rate = 200.0f;
                st->airMeterCurrent =
                    rate * timeDelta + st->airMeterCurrent;
                st->airMeterRefillTimer =
                    st->airMeterRefillTimer - (f32)(s32)(rate * timeDelta);
                st->airMeterRefillTimer =
                    (st->airMeterRefillTimer < lim)
                        ? lim
                        : ((st->airMeterRefillTimer > lbl_803E5B80) ? lbl_803E5B80 : st->airMeterRefillTimer);
                st->airMeterCurrent =
                    (st->airMeterCurrent < lbl_803E5AE8)
                        ? lbl_803E5AE8
                        : ((st->airMeterCurrent > st->airMeterMax)
                               ? st->airMeterMax
                               : st->airMeterCurrent);
            }
            if (st->airMeterCurrent < lbl_803E5B84)
            {
                Sfx_KeepAliveLoopedObjectSound((u32)obj, SFXTRIG_ar_bomb_pickup);
            }
            (*gGameUIInterface)->runAirMeter((s32)st->airMeterCurrent);
        }
        else
        {
            Sfx_StopObjectChannel((u32)obj, 0x7f);
            if (st->velLimitX > lbl_803E5B20)
            {
                if (randomGetRange(0, 10) == 0)
                {
                    Sfx_PlayFromObject(0, SFXsp_lfoot_taunt7);
                }
                PSVECScale(&st->velLimitX, &st->velLimitX, lbl_803E5B88);
                if ((u32)(st->flags428 >> 7 & 1) != 0)
                {
                    if (st->velLimitX < lbl_803E5B20)
                    {
                        st->velLimitX = *(f32 *)&lbl_803E5B20;
                    }
                }
            }
            else
            {
                (*gGameUIInterface)->airMeterSetShutdown();
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                lim = lbl_803E5B8C;
                st->velLimitX = lbl_803E5B8C;
                st->velLimitY = lim;
                st->velLimitZ = lim;
            }
        }
    }
}

typedef struct HightopFlags
{
    u8 resetLatch : 1;
    u8 flags : 7;
} HightopFlags;

void fn_801EB334(int* obj)
{
    SnowBikeState* state = ((GameObject*)obj)->extra;
    if ((u32)((state->flags428 >> 1) & 1) == 0)
    {
        s16 sv;
        f32 fz = lbl_803E5AE8;
        state->localVelX = fz;
        state->localVelY = fz;
        state->distanceScale = lbl_803E5B9C;
        ((HightopFlags*)&state->flags428)->resetLatch = 0;
        state->impactShakeTimer = fz;
        sv = *(s16*)obj;
        state->yaw = sv;
        state->yawCurrent = sv;
        state->unk430 = lbl_803E5B74;
    }
    ObjHits_EnableObject((u32)obj);
    (*gPathControlInterface)->attachObject((void*)obj, (char*)state + 0x178);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosX = ((GameObject*)obj)->anim.localPosX;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosY = ((GameObject*)obj)->anim.localPosY;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->localPosZ = ((GameObject*)obj)->anim.localPosZ;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosX = ((GameObject*)obj)->anim.worldPosX;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosY = ((GameObject*)obj)->anim.worldPosY;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->worldPosZ = ((GameObject*)obj)->anim.worldPosZ;
}

int SnowBike_animEventCallback(short* obj, int arg2, ObjSeqState* seq)
{
    typedef struct HightopMatrixSeed
    {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 unused;
        f32 x;
        f32 y;
        f32 z;
    } HightopMatrixSeed;

    u8 triggerType;
    int i;
    int state;
    f32 matrix[16];
    HightopMatrixSeed transform;
    f64 xSpeed;
    f64 ySpeed;
    f64 zSpeed;

    state = *(int*)(obj + 0x5c);
    seq->freeCallback = (ObjAnimSequenceFreeCallback)fn_801EB334;
    ObjHits_DisableObject((u32)obj);

    for (i = 0; i < (int)(u32)seq->eventCount; i++)
    {
        triggerType = seq->eventIds[i];
        switch (triggerType)
        {
        case 2:
            if (obj[0x23] != 0x16c && obj[0x23] != 0x16f)
            {
                GameBit_Set(0x499, 1);
            }
            break;
        case 3:
            (*gGameUIInterface)->airMeterSetShutdown();
            break;
        }
    }

    if (((SnowBikeState*)state)->riderMode == 2)
    {
        xSpeed = (double)(float)(oneOverTimeDelta *
            (*(float*)(obj + 6) - ((SnowBikeState*)state)->refPosX));
        ySpeed = (double)(float)(oneOverTimeDelta *
            (*(float*)(obj + 8) - ((SnowBikeState*)state)->refPosY));
        zSpeed = (double)(float)(oneOverTimeDelta *
            (*(float*)(obj + 10) - ((SnowBikeState*)state)->refPosZ));

        transform.x = lbl_803E5AE8;
        transform.y = lbl_803E5AE8;
        transform.z = lbl_803E5AE8;
        transform.unused = lbl_803E5AEC;
        transform.rotX = -*obj;
        transform.rotY = 0;
        transform.rotZ = 0;
        mtxRotateByVec3s(matrix, &transform);
        Matrix_TransformPoint(matrix, xSpeed, ySpeed, zSpeed, (float*)(state + 0x494),
                              (float*)(state + 0x498), (float*)(state + 0x49c));

        ((SnowBikeState*)state)->stickY = ((SnowBikeState*)state)->stickY + (framesThisStep << 3);
        if (((SnowBikeState*)state)->stickY > 0x46)
        {
            ((SnowBikeState*)state)->stickY = 0x46;
        }

        ((void (*)(int, int, f32, int, int, u8))fn_801EA240)(
            (int)obj, state, ((SnowBikeState*)state)->distanceScale,
            (int)(lbl_803E5BA0 * -((SnowBikeState*)state)->unk430),
            state + 0x461, 4);
    }

    ((HightopFlags3*)&((SnowBikeState*)state)->flags428)->active = 0;
    return 0;
}

void fn_801EB634(int obj, int stateRaw)
{
    extern int ObjHits_IsObjectEnabled(int obj); /* #11 */
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    int hitKind;
    int hitReact;
    int burstCount;
    u32 hit;
    f32 dot;
    int hitOutB;
    u32 hitOutC;
    int hitObj;
    f32 velNrm[3];

    hitReact = *(int*)&((GameObject*)obj)->anim.hitReactState;
    if (ObjHits_IsObjectEnabled(obj) != 0)
    {
        if ((u32)(st->flags428 >> 1 & 1) == 0)
        {
            ObjHits_SetHitVolumeSlot(obj, 0x15, 1, 0);
        }
        else
        {
            ObjHits_ClearHitVolumes(obj);
            ObjHits_SyncObjectPositionIfDirty(obj);
        }
        hitKind = ObjHits_GetPriorityHit(obj, &hitObj, &hitOutB, &hitOutC);
        switch (hitKind)
        {
        case 0xd:
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                st->linkedObj = hitObj;
                st->collisionFxDamping = lbl_803E5AEC;
            }
            break;
        case 0x15:
            if (st->collisionFxTimer == lbl_803E5AE8)
            {
                PSVECNormalize((float*)(obj + 0x24), velNrm);
                dot = PSVECDotProduct(velNrm, (float*)(hitObj + 0x24));
                PSVECScale(&st->localVelX, &st->localVelX,
                           dot * st->collisionBounceScale + lbl_803E5AEC);
                st->localVelY = st->localVelY * lbl_803E5BA8;
                st->collisionFxTimer = lbl_803E5AF4;
                st->collisionFxDamping = lbl_803E5AEC;
            }
            break;
        case 0x1d:
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                setMotionBlur(1, lbl_803E5BAC);
                st->collisionFxTimer = (f32)(s32)lbl_803DC0D0;
                st->collisionFxDamping = lbl_803DC0C8;
                st->airMeterRefillTimer = (f32)(s32)lbl_803DC0CC;
            }
            break;
        }
        hit = *(u32*)(hitReact + 0x50);
        if (((hit != 0) &&
                (hitObj = hit, *(u32*)&st->linkedObj = hit, st->collisionFxTimer == lbl_803E5AE8)) &&
            (hitKind = arrayIndexOf(gDrHighTopHitObjectKinds, 0xc, (int)*(short*)(hitObj + 0x46)), hitKind != -1))
        {
            fn_8009A8C8(obj, (double)lbl_803E5BB0);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x551, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x552, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x554, NULL, 4, -1, NULL);
            burstCount = 0x32 / framesThisStep;
            while (burstCount-- != 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x553, NULL, 2, -1, NULL);
            }
            st->collisionFxTimer = lbl_803E5AF4;
            st->collisionFxDamping = lbl_803E5AEC;
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                st->collisionFxTimer = (f32)(s32)lbl_803DC0D4;
            }
        }
    }
}

#pragma opt_lifetimes off
void fn_801EB940(short* obj, int stateRaw)
{
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    f32 fa;
    f32 fb;
    int rotClamped;
    int yawDelta;
    int ival;

    ival = stateRaw + 0x178;
    (*gPathControlInterface)->update(obj, (void*)ival, timeDelta);
    (*gPathControlInterface)->apply(obj, (void*)ival);
    (*gPathControlInterface)->advance(obj, (void*)ival, timeDelta);
    ival = 2;
    if (*(char*)(stateRaw + 0x3d9) == '\0')
    {
        st->impactShakeTimer = st->impactShakeTimer + timeDelta;
        fa = st->impactShakeTimer;
        st->impactShakeTimer =
            (fa < lbl_803E5AE8)
                ? lbl_803E5AE8
                : ((fa > lbl_803E5BB4) ? lbl_803E5BB4 : fa);
        if (st->impactShakeTimer >= lbl_803E5BB8)
        {
            if ((u32)(st->flags428 >> 7 & 1) == 0)
            {
                st->unk584 = lbl_803E5AE8;
            }
            ((HightopFlags*)&st->flags428)->resetLatch = 1;
        }
    }
    else
    {
        if ((u32)(st->flags428 >> 7 & 1) != 0)
        {
            ival = 0;
            fa = lbl_803E5BBC;
            st->haloYawDrift = fa * (f32)(s32)
            obj[1];
            st->haloDriftAmpB = fa * (f32)(s32)
            obj[2];
            st->haloDriftPhaseA = ival;
            st->haloDriftPhaseB = ival;
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                doRumble(st->impactShakeTimer * fa);
                Camera_EnableViewYOffset();
                CameraShake_SetAllMagnitudes(st->impactShakeTimer / lbl_803E5BC0);
                Sfx_PlayFromObject((u32)obj, SFXTRIG_tr_jbike_bombbeep);
                fb = (lbl_803E5B40 < lbl_803E5BC4 * st->impactShakeTimer)
                         ? lbl_803E5B40
                         : lbl_803E5BC4 * st->impactShakeTimer;
                {
                    Sfx_SetObjectSfxVolume((u32)obj, SFXTRIG_tr_jbike_bombbeep, fb, lbl_803E5B20);
                }
            }
        }
        ((HightopFlags*)&st->flags428)->resetLatch = 0;
        st->impactShakeTimer = lbl_803E5AE8;
        st->dampPresetMode = st->dampPresetModeRaw;
    }
    fa = lbl_803E5BC8;
    st->haloDriftPhaseA = fa * timeDelta + (f32)(s32)st->haloDriftPhaseA;
    st->haloDriftPhaseB = fa * timeDelta + (f32)(s32)st->haloDriftPhaseB;
    st->haloYawDrift =
        st->haloYawDrift * powfBitEstimate(lbl_803E5BCC, timeDelta);
    st->haloDriftAmpB =
        st->haloDriftAmpB * powfBitEstimate(lbl_803E5BCC, timeDelta);
    st->haloPitchDrift =
        st->haloYawDrift *
        mathSinf((gDrHighTopPi * (f32)(s32)st->haloDriftPhaseA) / lbl_803E5BD4);
    st->haloDriftB =
        st->haloDriftAmpB *
        mathSinf((gDrHighTopPi * (f32)(s32)st->haloDriftPhaseB) / lbl_803E5BD4);
    yawDelta = (int)*obj - ((int)st->yaw & 0xffffU);
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    st->yaw = *(s16*)((char*)st + 0x40e) + yawDelta;
    st->yawCurrent = st->yawCurrent + yawDelta;
    obj[1] = obj[1] + ((int)st->unk310 >> ival);
    obj[2] = obj[2] + ((int)st->unk312 >> ival);
    rotClamped = obj[1];
    if (rotClamped < -0x2000)
    {
        rotClamped = -0x2000;
    }
    else if (0x2000 < rotClamped)
    {
        rotClamped = 0x2000;
    }
    obj[1] = rotClamped;
    rotClamped = obj[2];
    if (rotClamped < -0x2000)
    {
        rotClamped = -0x2000;
    }
    else if (0x2000 < rotClamped)
    {
        rotClamped = 0x2000;
    }
    obj[2] = rotClamped;
}
#pragma opt_lifetimes reset


void fn_801EBD60(int obj, int stateRaw)
{
    typedef struct HightopPartfxTransform
    {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } HightopPartfxTransform;

    SnowBikeState* st = (SnowBikeState*)stateRaw;
    u8 flags;
    s16 motionFrame;
    f32 fa;
    f32 fb;
    f32 speed;
    f32 target558;
    f32 target530;
    f32 target534;
    f32 target548;
    f32 target54c;
    f32 target540;
    f32 target544;
    f32 k;
    HightopPartfxTransform effect;

    speed = sqrtf(st->distanceScale * st->distanceScale +
        (st->localVelX * st->localVelX +
            st->localVelY * st->localVelY));
    st->timer -= timeDelta;
    fa = st->timer;
    st->timer =
        (fa < lbl_803E5AE8)
            ? lbl_803E5AE8
            : ((fa > lbl_803E5B1C) ? lbl_803E5B1C : fa);

    flags = st->flags428;
    if ((u32)(flags >> 7 & 1) == 0)
    {
        switch (st->dampPresetMode)
        {
        case 0xd:
            target558 = lbl_803E5BD8;
            target534 = lbl_803E5BDC;
            target530 = lbl_803E5B88;
            target548 = lbl_803E5BE0;
            target54c = lbl_803E5BE4;
            target540 = lbl_803E5BE8;
            target544 = lbl_803E5AF8;
            if (((u32)(flags >> 1 & 1) == 0) &&
                (st->timer <= lbl_803E5AE8))
            {
                st->timer = (f32)(s32)
                randomGetRange(5, 10);
                if (PSVECMag((void*)(obj + 0x24)) > lbl_803E5BC4)
                {
                    doRumble((f32)(s32)randomGetRange(1, 3));
                }
            }
            if (speed > lbl_803E5BEC)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x80b, NULL, 2, -1, NULL);
            }
            break;
        case 3:
        default:
            target558 = lbl_803E5BF0;
            target534 = lbl_803E5BF4;
            target530 = lbl_803E5BF8;
            target548 = lbl_803E5BFC;
            target54c = lbl_803E5BE4;
            target540 = lbl_803E5BE8;
            target544 = lbl_803E5AF8;
            break;
        case 9:
            target558 = lbl_803E5BEC;
            target534 = lbl_803E5BF4;
            target530 = lbl_803E5C00;
            target548 = lbl_803E5C04;
            target54c = lbl_803E5C08;
            target540 = lbl_803E5B20;
            target544 = lbl_803E5C0C;
            if (speed > lbl_803E5B34)
            {
                effect.scale = lbl_803E5AEC;
                effect.rotZ = 0;
                effect.rotY = 0;
                effect.rotX = 0;
                effect.x = ((GameObject*)obj)->anim.localPosX;
                effect.y = lbl_803E5C10 + ((GameObject*)obj)->anim.localPosY;
                effect.z = ((GameObject*)obj)->anim.localPosZ;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x80a, &effect, 1, -1, NULL);
            }
            break;
        }

        motionFrame = st->steerAngleDeg;
        if (((motionFrame >= 0x1e) && (motionFrame <= 0x3c)) ||
            ((motionFrame >= 0x12c) && (motionFrame <= 0x14a)))
        {
            target558 *= lbl_803E5B20;
            target534 *= lbl_803E5B2C;
            target530 += lbl_803E5B20;
            if (target530 < lbl_803E5AE8)
            {
                target530 = lbl_803E5AE8;
            }
            else if (target530 > lbl_803E5B88)
            {
                target530 = lbl_803E5B88;
            }
        }
    }
    else
    {
        target558 = st->unk578;
        target534 = st->unk574;
        target530 = st->unk56C;
        target548 = st->localVelXDampTarget;
        target54c = st->distanceScaleDampTarget;
        target540 = lbl_803E5B20;
        target544 = lbl_803E5AF8;
    }

    if ((u32)((st->flags428 >> 1) & 1) != 0)
    {
        target558 = lbl_803E5AF8;
    }
    fb = timeDelta;
    speed = lbl_803E5C14;
    st->unk558 += fb * (speed *
        (((target558 < lbl_803E5BD8)
              ? lbl_803E5BD8
              : ((target558 > lbl_803E5AEC) ? lbl_803E5AEC : target558)) -
            st->unk558));
    st->unk534 += timeDelta * (lbl_803E5BBC * (target534 - st->unk534));
    st->unk530 += timeDelta * (lbl_803E5C14 * (target530 - st->unk530));
    st->localVelXDamp += timeDelta * ((k = lbl_803E5B20) * (target548 - st->localVelXDamp));
    st->distanceScaleDamp += timeDelta * (k * (target54c - st->distanceScaleDamp));
    st->turnVelScale += timeDelta * (k * (target540 - st->turnVelScale));
    st->turnForceGain += timeDelta * (k * (target544 - st->turnForceGain));
}

int gDrHighTopHitObjectKinds[] = {
    0x72, 0x16D, 0x170, 0x16C, 0x16F, 0x38C,
    0x389, 0x38A, 0x4D3, 0x38D, 0x38E, 0x4D4,
};
