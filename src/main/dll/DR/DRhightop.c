#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objhits_types.h"
#include "main/dll/BW/BWalphaanim.h"
#include "main/dll/DR/DRcloudcage.h"
#include "main/dll/DR/DRhightop.h"
#include "main/dll/path_control_interface.h"
#include "main/objseq.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80006c88();
extern void gameTextShow(int p);
extern void doRumble(f32 strength);
extern void mtxRotateByVec3s(void* matrix, void* transform);
extern void Matrix_TransformPoint(void* matrix, double x, double y, double z, float* outX,
                                  float* outY, float* outZ);
extern f32 PSVECMag(void* vec);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern uint FUN_80017730();
extern undefined4 FUN_8001774c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_IsObjectEnabled();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_80053c20();
extern int FUN_8005b398();
extern undefined4 FUN_800632e8();
extern int FUN_8007f3c8();
extern undefined4 FUN_80081124();
extern double FUN_801eac78();
extern undefined4 FUN_801ed004();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern double FUN_80247f90();
extern undefined4 FUN_80293130();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_8032916c;
extern undefined4 DAT_803adcf4;
extern undefined4 DAT_803add04;
extern undefined4 DAT_803dc070;
extern u8 framesThisStep;
extern f32 oneOverTimeDelta;
extern undefined4 DAT_803dcd24;
extern undefined4 DAT_803dcd34;
extern undefined4 DAT_803dcd38;
extern undefined4 DAT_803dcd3c;
extern undefined4 DAT_803dcd44;
extern undefined4* DAT_803dd6ec;
extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e6798;
extern f64 lbl_803E5B00;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DCD30;
extern f32 lbl_803DCD40;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B2C;
extern f32 lbl_803E5B34;
extern f32 lbl_803E5B80;
extern f32 lbl_803E5B84;
extern f32 lbl_803E5B88;
extern f32 lbl_803E5B8C;
extern f32 lbl_803DC0D8;
extern f32 lbl_803E5BA0;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern void PSVECScale(f32* dst, f32* src, f32 s);
extern void Sfx_KeepAliveLoopedObjectSound(uint obj, int sfxId);
extern void Sfx_StopObjectChannel(uint obj, int channel);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC4;
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
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E678C;
extern f32 lbl_803E67A0;
extern f32 lbl_803E67A8;
extern f32 lbl_803E67AC;
extern f32 lbl_803E67B8;
extern f32 lbl_803E67D8;
extern f32 lbl_803E6800;
extern f32 lbl_803E6804;
extern f32 lbl_803E6808;
extern f32 lbl_803E680C;
extern f32 lbl_803E6810;
extern f32 lbl_803E6814;
extern f32 lbl_803E6818;
extern f32 lbl_803E681C;
extern f32 lbl_803E6820;
extern f32 lbl_803E6824;
extern f32 lbl_803E6834;
extern f32 lbl_803E6838;
extern f32 lbl_803E6840;
extern f32 lbl_803E6844;
extern f32 lbl_803E6848;
extern f32 lbl_803E684C;
extern f32 lbl_803E6850;
extern f32 lbl_803E6854;
extern f32 lbl_803E6858;
extern f32 lbl_803E685C;
extern f32 lbl_803E6860;
extern f32 lbl_803E6864;

/*
 * --INFO--
 *
 * Function: fn_801EAE4C
 * EN v1.0 Address: 0x801EAE4C
 * EN v1.0 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int lbl_803DC0BC;
extern s16 lbl_803DC0DC;
extern f32 lbl_803E5B68;
extern f32 lbl_803E5B7C;
extern char lbl_803AD088[];
extern undefined4* gCheckpointInterface;
extern void SnowBike_func15();

typedef struct HightopFlags3
{
    u8 hi : 4;
    u8 active : 1;
    u8 lo : 3;
} HightopFlags3;

void fn_801EAE4C(short* obj, int stateRaw)
{
    float tickDir;
    float fVar2;
    uint bitVal;
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    short angDelta;
    uint absDelta;
    int iVar7;
    ushort uRet;
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
                (*(code*)(*gCheckpointInterface + 0x10))(obj, stateRaw + 0x28,
                                                         st->unk05C);
            }
            (*(code*)(*gCheckpointInterface + 0x28))(stateRaw + 0x28);
        }
    }
    else
    {
        if ((u32)(st->flags428 >> 1 & 1) == 0)
        {
            uRet = (*(code*)(*gCheckpointInterface + 0x14))(obj, stateRaw + 0x28);
            angDelta = *obj - uRet;
            if (0x8000 < angDelta)
            {
                angDelta = angDelta - 0xffff;
            }
            if (angDelta < -0x8000)
            {
                angDelta = angDelta + 0xffff;
            }
            absDelta = (uint)angDelta;
            if ((int)absDelta < 0)
            {
                absDelta = -absDelta;
            }
            if ((int)((uint)(((int)(absDelta ^ lbl_803DC0DC) >> 1) - ((absDelta ^ lbl_803DC0DC) & absDelta)) >> 0x1f) ==
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
            (*(code*)(*gCheckpointInterface + 0x2c))(stateRaw + 0x28);
            st->unk422 = (s8)(*(code*)(*gCheckpointInterface + 0x34))(stateRaw + 0x28);
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
    return;
}

/*
 * --INFO--
 *
 * Function: fn_801EB0D4
 * EN v1.0 Address: 0x801EB0D4
 * EN v1.0 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801EB0D4(uint param_1, int param_2)
{
    SnowBikeState* st = (SnowBikeState*)param_2;
    float fVar1;
    float fVar2;
    float fVar3;
    float td;
    float v;

    if ((u32)(st->flags428 >> 5 & 1) != 0)
    {
        if (st->airMeterCurrent >= lbl_803E5AE8)
        {
            td = timeDelta;
            st->airMeterCurrent -=
                td * lbl_803DC0D8 + (f32)(s32)(st->airDrainRate *
                    (td * PSVECMag(&st->unk494)));
            fVar2 = lbl_803E5AE8;
            if (fVar2 != st->unk4C4)
            {
                fVar3 = lbl_803E5B14;
                st->airMeterCurrent =
                    fVar3 * timeDelta + st->airMeterCurrent;
                st->unk4C4 =
                    st->unk4C4 - (f32)(s32)(fVar3 * timeDelta);
                fVar1 = st->unk4C4;
                st->unk4C4 =
                    (fVar1 < fVar2)
                        ? fVar2
                        : ((fVar1 > lbl_803E5B80) ? lbl_803E5B80 : fVar1);
                fVar1 = st->airMeterCurrent;
                st->airMeterCurrent =
                    (fVar1 < lbl_803E5AE8)
                        ? lbl_803E5AE8
                        : ((fVar1 > st->airMeterMax)
                               ? st->airMeterMax
                               : fVar1);
            }
            if (st->airMeterCurrent < lbl_803E5B84)
            {
                Sfx_KeepAliveLoopedObjectSound(param_1, 0x44e);
            }
            (*gGameUIInterface)->runAirMeter((s32)st->airMeterCurrent);
        }
        else
        {
            Sfx_StopObjectChannel(param_1, 0x7f);
            if (st->unk464 > lbl_803E5B20)
            {
                if ((u32)randomGetRange(0, 10) == 0)
                {
                    Sfx_PlayFromObject(0, SFXsp_lfoot_taunt7);
                }
                PSVECScale(&st->unk464, &st->unk464, lbl_803E5B88);
                if ((u32)(st->flags428 >> 7 & 1) != 0)
                {
                    if (st->unk464 < lbl_803E5B20)
                    {
                        st->unk464 = lbl_803E5B20;
                    }
                }
            }
            else
            {
                (*gGameUIInterface)->airMeterSetShutdown();
                (*gObjectTriggerInterface)->runSequence(0, (void*)param_1, -1);
                fVar2 = lbl_803E5B8C;
                st->unk464 = lbl_803E5B8C;
                st->unk468 = fVar2;
                st->unk46C = fVar2;
            }
        }
    }
    return;
}

extern f32 lbl_803E5B9C;
extern f32 lbl_803E5B74;

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
        state->unk494 = fz;
        state->unk498 = fz;
        state->distanceScale = lbl_803E5B9C;
        ((HightopFlags*)&state->flags428)->resetLatch = 0;
        state->unk424 = fz;
        sv = *(s16*)obj;
        state->yaw = sv;
        state->unk40C = sv;
        state->unk430 = lbl_803E5B74;
    }
    ObjHits_EnableObject(obj);
    (*gPathControlInterface)->attachObject((void*)obj, (char*)state + 0x178);
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->localPosX = ((GameObject*)obj)->anim.localPosX;
        hitState->localPosY = ((GameObject*)obj)->anim.localPosY;
        hitState->localPosZ = ((GameObject*)obj)->anim.localPosZ;
        hitState->worldPosX = ((GameObject*)obj)->anim.worldPosX;
        hitState->worldPosY = ((GameObject*)obj)->anim.worldPosY;
        hitState->worldPosZ = ((GameObject*)obj)->anim.worldPosZ;
    }
}

/*
 * --INFO--
 *
 * Function: SnowBike_animEventCallback
 * EN v1.0 Address: 0x801EB420
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801EBA58
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 SnowBike_animEventCallback(short* param_1, undefined4 param_2, ObjSeqState* seq)
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
    float matrix[16];
    HightopMatrixSeed transform;
    double xSpeed;
    double ySpeed;
    double zSpeed;

    state = *(int*)(param_1 + 0x5c);
    seq->freeCallback = (ObjAnimSequenceFreeCallback)fn_801EB334;
    ObjHits_DisableObject((int)param_1);

    for (i = 0; i < (int)(uint)seq->eventCount; i++)
    {
        triggerType = seq->eventIds[i];
        switch (triggerType)
        {
        case 2:
            if (param_1[0x23] != 0x16c && param_1[0x23] != 0x16f)
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
            (*(float*)(param_1 + 6) - ((SnowBikeState*)state)->unk16C));
        ySpeed = (double)(float)(oneOverTimeDelta *
            (*(float*)(param_1 + 8) - ((SnowBikeState*)state)->unk170));
        zSpeed = (double)(float)(oneOverTimeDelta *
            (*(float*)(param_1 + 10) - ((SnowBikeState*)state)->unk174));

        transform.x = lbl_803E5AE8;
        transform.y = lbl_803E5AE8;
        transform.z = lbl_803E5AE8;
        transform.unused = lbl_803E5AEC;
        transform.rotX = -*param_1;
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

        fn_801EA240(((SnowBikeState*)state)->distanceScale, (int)param_1, state,
                    (int)(lbl_803E5BA0 * -((SnowBikeState*)state)->unk430),
                    state + 0x461, 4);
    }

    ((HightopFlags3*)&((SnowBikeState*)state)->flags428)->active = 0;
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801EB634
 * EN v1.0 Address: 0x801EB634
 * EN v1.0 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E5AF4;
extern f32 lbl_803E5BA8;
extern f32 lbl_803E5BAC;
extern f32 lbl_803E5BB0;
extern int lbl_803DC0D0;
extern f32 lbl_803DC0C8;
extern int lbl_803DC0CC;
extern int lbl_803DC0D4;
extern int lbl_8032852C[];
extern void PSVECNormalize(void* src, void* dst);
extern f32 PSVECDotProduct(void* a, void* b);
extern void setMotionBlur(double amount, int p2);
extern void fn_8009A8C8();
extern int arrayIndexOf();

void fn_801EB634(int obj, int stateRaw)
{
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    int hitKind;
    int hitReact;
    int burstCount;
    uint hit;
    f32 dot;
    int hitOutB;
    uint hitOutC;
    uint hitObj;
    float velNrm[3];

    hitReact = *(int*)(obj + 0x54);
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
                st->unk42C = hitObj;
                st->collisionFxDamping = lbl_803E5AEC;
            }
            break;
        case 0x15:
            if (st->collisionFxTimer == lbl_803E5AE8)
            {
                PSVECNormalize((float*)(obj + 0x24), velNrm);
                dot = PSVECDotProduct(velNrm, (float*)(hitObj + 0x24));
                PSVECScale(&st->unk494, &st->unk494,
                           dot * st->unk4AC + lbl_803E5AEC);
                st->unk498 = st->unk498 * lbl_803E5BA8;
                st->collisionFxTimer = lbl_803E5AF4;
                st->collisionFxDamping = lbl_803E5AEC;
            }
            break;
        case 0x1d:
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                setMotionBlur(lbl_803E5BAC, 1);
                st->collisionFxTimer = (f32)(s32)
                lbl_803DC0D0;
                st->collisionFxDamping = lbl_803DC0C8;
                st->unk4C4 = (f32)(s32)
                lbl_803DC0CC;
            }
            break;
        }
        hit = *(uint*)(hitReact + 0x50);
        if (((hit != 0) &&
                (hitObj = hit, *(u32*)&st->unk42C = hit, st->collisionFxTimer == lbl_803E5AE8)) &&
            (hitKind = arrayIndexOf(lbl_8032852C, 0xc, (int)*(short*)(hitObj + 0x46)), hitKind != -1))
        {
            fn_8009A8C8((double)lbl_803E5BB0, obj);
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
                st->collisionFxTimer = (f32)(s32)
                lbl_803DC0D4;
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_801EB940
 * EN v1.0 Address: 0x801EB940
 * EN v1.0 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct HightopFlagsB
{
    u8 resetLatch : 1;
    u8 flags : 7;
} HightopFlagsB;

extern f32 lbl_803E5BB4;
extern f32 lbl_803E5BB8;
extern f32 lbl_803E5BC0;
extern f32 lbl_803E5B40;
extern f32 lbl_803E5BC8;
extern f32 lbl_803E5BCC;
extern f32 lbl_803E5BD0;
extern f32 lbl_803E5BD4;
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern void Sfx_SetObjectSfxVolume(f32 ratio, s16* obj, int sfx, int vol);
extern f32 powfBitEstimate(f32 base, f32 exp);
extern f32 mathSinf(f32 x);

void fn_801EB940(short* obj, int stateRaw)
{
    SnowBikeState* st = (SnowBikeState*)stateRaw;
    float fa;
    float fb;
    short rotClamped;
    int yawDelta;
    int ival;

    ival = stateRaw + 0x178;
    (*gPathControlInterface)->update(obj, (void*)ival, timeDelta);
    (*gPathControlInterface)->apply(obj, (void*)ival);
    (*gPathControlInterface)->advance(obj, (void*)ival, timeDelta);
    ival = 2;
    if (*(char*)(stateRaw + 0x3d9) == '\0')
    {
        st->unk424 = st->unk424 + timeDelta;
        fa = st->unk424;
        st->unk424 =
            (fa < lbl_803E5AE8)
                ? lbl_803E5AE8
                : ((fa > lbl_803E5BB4) ? lbl_803E5BB4 : fa);
        if (st->unk424 >= lbl_803E5BB8)
        {
            if ((u32)(st->flags428 >> 7 & 1) == 0)
            {
                st->unk584 = lbl_803E5AE8;
            }
            ((HightopFlagsB*)&st->flags428)->resetLatch = 1;
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
            st->unk590 = fa * (f32)(s32)
            obj[2];
            st->unk588 = ival;
            st->unk58A = ival;
            if ((u32)(st->flags428 >> 1 & 1) == 0)
            {
                doRumble(st->unk424 * fa);
                Camera_EnableViewYOffset();
                CameraShake_SetAllMagnitudes(st->unk424 / lbl_803E5BC0);
                Sfx_PlayFromObject((int)obj, 0x3bc);
                fb = (lbl_803E5B40 < lbl_803E5BC4 * st->unk424)
                         ? lbl_803E5B40
                         : lbl_803E5BC4 * st->unk424;
                Sfx_SetObjectSfxVolume(lbl_803E5B20, obj, 0x3bc, (int)fb);
            }
        }
        ((HightopFlagsB*)&st->flags428)->resetLatch = 0;
        st->unk424 = lbl_803E5AE8;
        st->unk4B4 = st->unk230;
    }
    fa = lbl_803E5BC8;
    st->unk588 =
        fa * timeDelta + (f32)(s32)
    st->unk588;
    st->unk58A =
        fa * timeDelta + (f32)(s32)
    st->unk58A;
    st->haloYawDrift =
        st->haloYawDrift * powfBitEstimate(lbl_803E5BCC, timeDelta);
    st->unk590 =
        st->unk590 * powfBitEstimate(lbl_803E5BCC, timeDelta);
    st->haloPitchDrift =
        st->haloYawDrift *
        mathSinf((lbl_803E5BD0 * (f32)(s32)st->unk588) / lbl_803E5BD4
    )
    ;
    st->unk598 =
        st->unk590 *
        mathSinf((lbl_803E5BD0 * (f32)(s32)st->unk58A) / lbl_803E5BD4
    )
    ;
    yawDelta = (int)*obj - ((int)st->yaw & 0xffffU);
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    st->yaw = st->yaw + (short)yawDelta;
    st->unk40C = st->unk40C + (short)yawDelta;
    obj[1] = obj[1] + (short)((int)st->unk310 >> ival);
    obj[2] = obj[2] + (short)((int)st->unk312 >> ival);
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
    return;
}

/*
 * --INFO--
 *
 * Function: fn_801EBD60
 * EN v1.0 Address: 0x801EBD60
 * EN v1.0 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 sqrtf(f32);

void fn_801EBD60(int param_1, int param_2)
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

    SnowBikeState* st = (SnowBikeState*)param_2;
    u8 flags;
    s16 motionFrame;
    f32 fVar1;
    f32 fVar2;
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
        (st->unk494 * st->unk494 +
            st->unk498 * st->unk498));
    st->unk43C -= timeDelta;
    fVar1 = st->unk43C;
    st->unk43C =
        (fVar1 < lbl_803E5AE8)
            ? lbl_803E5AE8
            : ((fVar1 > lbl_803E5B1C) ? lbl_803E5B1C : fVar1);

    flags = st->flags428;
    if ((u32)(flags >> 7 & 1) == 0)
    {
        switch (st->unk4B4)
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
                (st->unk43C <= lbl_803E5AE8))
            {
                st->unk43C = (f32)(s32)
                randomGetRange(5, 10);
                if (PSVECMag((void*)(param_1 + 0x24)) > lbl_803E5BC4)
                {
                    doRumble((f32)(s32)randomGetRange(1, 3));
                }
            }
            if (speed > lbl_803E5BEC)
            {
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x80b, NULL, 2, -1, NULL);
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
                effect.x = *(f32*)(param_1 + 0xc);
                effect.y = lbl_803E5C10 + *(f32*)(param_1 + 0x10);
                effect.z = *(f32*)(param_1 + 0x14);
                (*gPartfxInterface)->spawnObject((void*)param_1, 0x80a, &effect, 1, -1, NULL);
            }
            break;
        }

        motionFrame = st->unk44C;
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
        target548 = st->unk57C;
        target54c = st->unk580;
        target540 = lbl_803E5B20;
        target544 = lbl_803E5AF8;
    }

    if ((u32)((st->flags428 >> 1) & 1) != 0)
    {
        target558 = lbl_803E5AF8;
    }
    st->unk558 += timeDelta * (lbl_803E5C14 *
        (((target558 < lbl_803E5BD8)
              ? lbl_803E5BD8
              : ((target558 > lbl_803E5AEC) ? lbl_803E5AEC : target558)) -
            st->unk558));
    st->unk534 += timeDelta * (lbl_803E5BBC * (target534 - st->unk534));
    st->unk530 += timeDelta * (lbl_803E5C14 * (target530 - st->unk530));
    st->unk548 += timeDelta * ((k = lbl_803E5B20) * (target548 - st->unk548));
    st->unk54C += timeDelta * (k * (target54c - st->unk54C));
    st->unk540 += timeDelta * (k * (target540 - st->unk540));
    st->unk544 += timeDelta * (k * (target544 - st->unk544));
}
