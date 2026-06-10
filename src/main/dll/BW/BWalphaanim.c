#include "main/dll/BW/BWalphaanim.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/dll/curves.h"
#include "main/dll/path_control_interface.h"


extern undefined4 FUN_8000680c();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017730();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017a10();
extern undefined4 FUN_80017a80();
extern int FUN_80053c14();
extern undefined4 FUN_80053c20();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern uint FUN_801eb0c0();
extern undefined4 fn_801EAE4C();
extern undefined4 fn_801EB0D4();
extern undefined4 fn_801EB634();
extern void fn_801EC1AC(int obj,int state);
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80293130();

extern f64 DOUBLE_803e6798;
extern f64 DOUBLE_803e68b8;
extern f32 lbl_803DC074;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6804;
extern f32 lbl_803E6808;
extern f32 lbl_803E6838;
extern f32 lbl_803E68B0;

extern void textureFree(u32);
extern u32 textureLoadAsset(int);
extern u32 lbl_803DDC60;

void SnowBike_release(void) {
    if (lbl_803DDC60 != 0) {
        textureFree(lbl_803DDC60);
        lbl_803DDC60 = 0;
    }
}
void SnowBike_initialise(void) {
    if (lbl_803DDC60 == 0) {
        lbl_803DDC60 = textureLoadAsset(0x186);
    }
}

void SB_CloudRunner_onSeqFree(int *obj) {
    SnowBikeState *p = (SnowBikeState *)obj[0xb8/4];
    p->riderPosX = ((GameObject *)obj)->anim.localPosX;
    p->riderPosY = ((GameObject *)obj)->anim.localPosY;
    p->riderPosZ = ((GameObject *)obj)->anim.localPosZ;
    {
        s32 v = *(s16*)obj - 0x4000;
        p->riderYawOnFree = (s16)v;
    }
    p->riderPitchOnFree = ((GameObject *)obj)->anim.rotZ;
}

extern char lbl_803284E0[];
extern u32 lbl_803E5AE0;
extern u8 *mmAlloc(int size, int tag, int a);
extern void *memcpy(void *dst, const void *src, int n);
extern void Obj_ClearModelSlotIndex(int obj);
extern void fn_801EC928(int obj, u8 *state);
extern void SnowBike_animEventCallback();
extern void ObjGroup_AddObject(int obj, int group);
extern f32 lbl_803DC0B8;
extern f32 lbl_803DC0C0;
extern f32 lbl_803DC0C4;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B90;
extern f32 lbl_803E5B94;
extern f32 lbl_803E5B98;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5C50;
extern f32 lbl_803E5C54;
extern f32 lbl_803E5C58;
extern f32 lbl_803E5C5C;
extern f32 lbl_803E5C60;
extern f32 lbl_803E5C64;
extern f32 lbl_803E5C68;

typedef struct {
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} SnowBikeFlags;

void SnowBike_init(int obj, u8 *params, int flag)
{
    char *base = lbl_803284E0;
    u32 pathParam = lbl_803E5AE0;
    u8 *state = ((GameObject *)obj)->extra;
    u8 *alloc;
    u8 *path;
    int i;
    s16 rot;
    f32 fz;
    f32 fv;

    if (((GameObject *)obj)->anim.mapEventSlot == 0x13) {
        alloc = mmAlloc(36, 5, 0);
        memcpy(alloc, params, 36);
        *(u8 **)&((GameObject *)obj)->anim.placementData = alloc;
        ((GameObject *)obj)->anim.flags |= 0x2000;
        Obj_ClearModelSlotIndex(obj);
    }
    rot = params[0x18] << 8;
    ((SnowBikeState *)state)->unk40C = rot;
    ((SnowBikeState *)state)->yaw = rot;
    *(s16 *)obj = rot;
    fn_801EC928(obj, state);
    if (flag == 0) {
        if (((SnowBikeFlags *)(state + 0x428))->b20) {
            ((SnowBikeState *)state)->airMeterMax = lbl_803E5B90;
            ((SnowBikeState *)state)->airDrainRate = lbl_803E5AEC;
            ((SnowBikeState *)state)->airMeterCurrent = lbl_803E5B94;
            if (((SnowBikeState *)state)->riderMode == 2) {
                (*gGameUIInterface)->initAirMeter((int)((SnowBikeState *)state)->airMeterMax, 1485);
                (*gGameUIInterface)->airMeterSetRatio(lbl_803E5B98);
            }
        }
    }
    if (params[0x19] != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b02 = 1;
    }
    ((SnowBikeState *)state)->checkpointIndexA = -1;
    ((SnowBikeState *)state)->checkpointIndexB = -1;
    ((SnowBikeState *)state)->checkpointIndexC = -1;
    ((SnowBikeState *)state)->unk05C = params[0x1c];
    ((SnowBikeState *)state)->unk05D = params[0x1d];
    ((SnowBikeState *)state)->unk00C = ((GameObject *)obj)->anim.localPosX;
    ((SnowBikeState *)state)->unk010 = ((GameObject *)obj)->anim.localPosY;
    ((SnowBikeState *)state)->unk014 = ((GameObject *)obj)->anim.localPosZ;
    ((GameObject *)obj)->animEventCallback = (void *)SnowBike_animEventCallback;
    ObjGroup_AddObject(obj, 10);
    if (flag == 0) {
        i = 0;
        for (path = state; i < 9; i++) {
            *(u8 **)(path + 0x4c8) = mmAlloc(1600, 26, 0);
            path += 8;
        }
    }
    ((SnowBikeState *)state)->homePosX = ((GameObject *)obj)->anim.worldPosX;
    ((SnowBikeState *)state)->homePosY = ((GameObject *)obj)->anim.worldPosY;
    ((SnowBikeState *)state)->homePosZ = ((GameObject *)obj)->anim.worldPosZ;
    ((SnowBikeState *)state)->pathProgress = lbl_803E5AE8;
    ((SnowBikeState *)state)->unk448 = *(s16 *)(params + 0x1a);
    ((SnowBikeState *)state)->gameBitId = *(s16 *)(params + 0x1e);
    if (GameBit_Get(((SnowBikeState *)state)->gameBitId) != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b04 = 1;
    }
    ((SnowBikeState *)state)->unk438 = lbl_803E5B1C;
    fz = lbl_803E5AE8;
    ((SnowBikeState *)state)->unk3F4 = fz;
    ((SnowBikeState *)state)->unk3F8 = fz;
    ((SnowBikeState *)state)->unk018 = lbl_803E5C48;
    ((SnowBikeState *)state)->unk01C = fz;
    ((SnowBikeState *)state)->unk020 = lbl_803E5BC4;
    ((SnowBikeState *)state)->unk024 = lbl_803E5C50;
    ((SnowBikeState *)state)->unk065 = -1;
    fv = lbl_803E5B98;
    ((SnowBikeState *)state)->unk464 = fv;
    ((SnowBikeState *)state)->unk468 = fv;
    ((SnowBikeState *)state)->modelId = 0x436;
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x72:
    default:
        ((SnowBikeState *)state)->bikeType = 1;
        ((SnowBikeState *)state)->unk46C = lbl_803E5C50;
        ((SnowBikeState *)state)->modelId = 282;
        break;
    case 0x16c:
        ((SnowBikeState *)state)->bikeType = 1;
        ((SnowBikeState *)state)->bikeVariant = 0;
        ((SnowBikeState *)state)->unk01C = lbl_803E5B14;
        ((SnowBikeState *)state)->unk018 = lbl_803E5C54;
        ((SnowBikeState *)state)->unk065 = 1;
        ((SnowBikeState *)state)->unk46C = lbl_803E5AF0;
        break;
    case 0x16f:
        ((SnowBikeState *)state)->bikeType = 1;
        ((SnowBikeState *)state)->unk058 = 1;
        ((SnowBikeState *)state)->bikeVariant = 1;
        ((SnowBikeState *)state)->unk065 = 2;
        ((SnowBikeState *)state)->unk46C = lbl_803E5AF0;
        break;
    case 0x38c:
        ((SnowBikeState *)state)->bikeType = 0;
        ((SnowBikeState *)state)->unk46C = lbl_803DC0C4;
        ((SnowBikeState *)state)->modelId = 282;
        break;
    case 0x38d:
        ((SnowBikeState *)state)->bikeType = 0;
        ((SnowBikeState *)state)->bikeVariant = 0;
        ((SnowBikeState *)state)->unk01C = lbl_803E5B14;
        ((SnowBikeState *)state)->unk018 = lbl_803E5C54;
        ((SnowBikeState *)state)->unk46C = lbl_803E5C58 * lbl_803DC0C0;
        break;
    case 0x38e:
        ((SnowBikeState *)state)->bikeType = 0;
        ((SnowBikeState *)state)->bikeVariant = 1;
        ((SnowBikeState *)state)->unk01C = lbl_803E5B48;
        ((SnowBikeState *)state)->unk018 = lbl_803E5C5C;
        ((SnowBikeState *)state)->unk46C = lbl_803E5C60 * lbl_803DC0C0;
        break;
    case 0x4d4:
        ((SnowBikeState *)state)->bikeType = 0;
        ((SnowBikeState *)state)->bikeVariant = 2;
        ((SnowBikeState *)state)->unk01C = lbl_803E5B48;
        ((SnowBikeState *)state)->unk018 = lbl_803E5C5C;
        ((SnowBikeState *)state)->unk46C = lbl_803DC0C0;
        break;
    }
    fv = ((SnowBikeState *)state)->unk464;
    ((SnowBikeState *)state)->unk47C = fv;
    ((SnowBikeState *)state)->unk470 = fv;
    fv = ((SnowBikeState *)state)->unk468;
    ((SnowBikeState *)state)->unk480 = fv;
    ((SnowBikeState *)state)->unk474 = fv;
    fv = ((SnowBikeState *)state)->unk46C;
    ((SnowBikeState *)state)->unk484 = fv;
    ((SnowBikeState *)state)->unk478 = fv;
    ((SnowBikeState *)state)->unk060 = base + ((SnowBikeState *)state)->bikeType * 6 + 0xa4;
    if (((SnowBikeState *)state)->bikeType == 0) {
        if (!((SnowBikeFlags *)(state + 0x428))->b02) {
            ((SnowBikeFlags *)(state + 0x428))->b20 = 1;
            ((SnowBikeState *)state)->unk4C4 = lbl_803E5AE8;
        }
        ((SnowBikeState *)state)->unk538 = lbl_803E5C64;
    } else {
        ((SnowBikeState *)state)->unk538 = lbl_803E5B74;
    }
    path = state + 0x178;
    path[0x25b] = 1;
    (*gPathControlInterface)->init(path, 0, 0x48607, 1);
    (*gPathControlInterface)->setup(path, 4, base, base + 0x30, &pathParam);
    if (((SnowBikeFlags *)(state + 0x428))->b02 && ((SnowBikeState *)state)->unk065 != -1) {
        curves_setLocalPointCollisionEx((CurvesCollisionState *)path, 1, (f32 *)(base + 0x40),
                                        &lbl_803DC0B8, 8, ((SnowBikeState *)state)->unk065);
    } else {
        (*gPathControlInterface)->setLocalPointCollision(path, 1, base + 0x40, &lbl_803DC0B8, 8);
    }
    path[0x264] = lbl_803E5C68 + lbl_803DC0B8;
    (*gPathControlInterface)->attachObject((void *)obj, path);
}


extern void Obj_SetModelSlotIndex(int obj, int slot);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int drshackle_updateAttachedPosition(int obj, u8 *state);
extern void fn_801EBD60(int obj, u8 *state);
extern void fn_801EC7A0(int obj, u8 *state);
extern void fn_801EA240(int obj, u8 *state, f32 speed, int val, u8 *p, int n);

typedef struct {
    s16 rot[3];
    f32 quad[4];
} SBRotQuad;
extern void objApplyVelocity(int obj);
extern int Rcp_GetMotionBlurEnabled(void);
extern void setMotionBlur(int a, f32 b);
extern void PSVECScale(f32 *src, f32 *dst, f32 scale);
extern void PSVECAdd(f32 *a, f32 *b, f32 *dst);
extern void mtxRotateByVec3s(f32 *mtx, s16 *rot);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern f32 powfBitEstimate(f32 x, f32 y);
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern char padGetStickX(int pad);
extern char padGetStickY(int pad);
extern u32 getButtonsHeld(int pad);
extern u32 getButtonsJustPressed(int pad);
extern u32 getButtonsJustPressedIfNotBusy(int pad);
extern int getAngle(f32 dx, f32 dz);
extern f32 timeDelta;
extern f32 lbl_803E5B6C;
extern f32 lbl_803E5B70;
extern f32 lbl_803E5BA0;
extern f32 lbl_803E5C18;

void SnowBike_update(int obj)
{
    u8 *state = ((GameObject *)obj)->extra;
    f32 mtx1[16];
    f32 mtx2[16];
    SBRotQuad rq1;
    SBRotQuad rq2;
    f32 vec1[3];
    f32 vec2[3];
    f32 dummy1;
    f32 dummy2;
    s8 mode;
    int t;
    f32 fz;
    f32 p;
    f32 v;
    f32 c;

    if (((GameObject *)obj)->anim.mapEventSlot == -1) {
        if (GameBit_Get(0x1fa) != 0) {
            ((SnowBikeState *)state)->unk420 = 0;
        }
        if (GameBit_Get(0x1fb) != 0) {
            Obj_SetModelSlotIndex(obj, 0x13);
        }
    }
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    ((GameObject *)obj)->anim.rotY = ((SnowBikeState *)state)->unk41C;
    ((GameObject *)obj)->anim.rotZ = ((SnowBikeState *)state)->unk41E;
    if (((SnowBikeFlags *)(state + 0x428))->b04 || GameBit_Get(((SnowBikeState *)state)->gameBitId) != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b04 = 1;
        return;
    }
    mode = ((SnowBikeState *)state)->riderMode;
    switch (mode) {
    case 0:
        {
            {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
                if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
                    ((SnowBikeState *)state)->unk420 = 1;
                } else {
                    ((SnowBikeState *)state)->unk420 = 0;
                }
                Sfx_StopObjectChannel(obj, 0x57);
            }
        }
        break;
    case 2:
        {
            fn_801EAE4C(obj, state);
            if (((SnowBikeFlags *)(state + 0x428))->b02) {
                if (drshackle_updateAttachedPosition(obj, state) != 0) {
                    fn_801EBD60(obj, state);
                    fn_801EC7A0(obj, state);
                    if (((SnowBikeState *)state)->collisionFxTimer != lbl_803E5AE8) {
                        PSVECScale((f32 *)(state + 0x464), (f32 *)(state + 0x47c), ((SnowBikeState *)state)->collisionFxDamping);
                        PSVECScale((f32 *)(state + 0x494), (f32 *)(state + 0x494), ((SnowBikeState *)state)->collisionFxDamping);
                        ((SnowBikeState *)state)->collisionFxTimer -= timeDelta;
                        if (((SnowBikeState *)state)->collisionFxTimer <= lbl_803E5AE8) {
                            if (Rcp_GetMotionBlurEnabled() != 0) {
                                setMotionBlur(0, lbl_803E5AE8);
                            }
                            ((SnowBikeState *)state)->collisionFxTimer = lbl_803E5AE8;
                        }
                    } else {
                        ((SnowBikeState *)state)->unk47C = ((SnowBikeState *)state)->unk464;
                        ((SnowBikeState *)state)->unk480 = ((SnowBikeState *)state)->unk468;
                        ((SnowBikeState *)state)->unk484 = ((SnowBikeState *)state)->unk46C;
                    }
                    fz = lbl_803E5AE8;
                    rq1.quad[1] = fz;
                    rq1.quad[2] = fz;
                    rq1.quad[3] = fz;
                    rq1.quad[0] = lbl_803E5AEC;
                    rq1.rot[0] = -((SnowBikeState *)state)->yaw;
                    rq1.rot[1] = -((GameObject *)obj)->anim.rotY;
                    rq1.rot[2] = -((GameObject *)obj)->anim.rotZ;
                    mtxRotateByVec3s(mtx1, rq1.rot);
                    Matrix_TransformPoint(mtx1, lbl_803E5AE8, ((SnowBikeState *)state)->unk4B0 * ((SnowBikeState *)state)->unk544, lbl_803E5AE8, &vec1[0], &dummy1, &vec1[2]);
                    vec1[0] = vec1[0] * ((SnowBikeState *)state)->unk540;
                    vec1[1] = lbl_803E5AE8;
                    PSVECScale(vec1, vec1, timeDelta);
                    PSVECAdd((f32 *)(state + 0x494), vec1, (f32 *)(state + 0x494));
                    ((SnowBikeState *)state)->unk498 = ((SnowBikeState *)state)->unk4B0 * timeDelta + ((SnowBikeState *)state)->unk498;
                    p = powfBitEstimate(((SnowBikeState *)state)->unk548, timeDelta);
                    ((SnowBikeState *)state)->unk494 *= p;
                    p = powfBitEstimate(((SnowBikeState *)state)->unk54C, timeDelta);
                    ((SnowBikeState *)state)->unk49C *= p;
                    fn_801EC1AC(obj, (int)state);
                    Matrix_TransformPoint((f32 *)(state + 0xec), ((SnowBikeState *)state)->unk494, ((SnowBikeState *)state)->unk498, ((SnowBikeState *)state)->unk49C, &((GameObject *)obj)->anim.velocityX, &((GameObject *)obj)->anim.velocityY, &((GameObject *)obj)->anim.velocityZ);
                    objApplyVelocity(obj);
                }
            } else {
                setAButtonIcon(0x10);
                setBButtonIcon(0x11);
                ((SnowBikeState *)state)->stickX = (f32)padGetStickX(0);
                ((SnowBikeState *)state)->stickY = (f32)padGetStickY(0);
                ((SnowBikeState *)state)->buttonsHeld = getButtonsHeld(0);
                ((SnowBikeState *)state)->buttonsJustPressed = getButtonsJustPressed(0);
                ((SnowBikeState *)state)->buttonsJustPressedIfNotBusy = getButtonsJustPressedIfNotBusy(0);
                ((SnowBikeState *)state)->unk44C = (f32)(u16)getAngle(((SnowBikeState *)state)->stickX, (f32)-(int)((SnowBikeState *)state)->stickY) / lbl_803E5C18;
                ((SnowBikeState *)state)->stickX = ((SnowBikeState *)state)->stickX / lbl_803E5B6C;
                v = ((SnowBikeState *)state)->stickX;
                if (v < lbl_803E5B70) {
                    c = lbl_803E5B70;
                } else if (v > lbl_803E5AEC) {
                    c = lbl_803E5AEC;
                } else {
                    c = v;
                }
                ((SnowBikeState *)state)->stickX = c;
                fn_801EBD60(obj, state);
                fn_801EC7A0(obj, state);
                if (((SnowBikeState *)state)->collisionFxTimer != lbl_803E5AE8) {
                    PSVECScale((f32 *)(state + 0x464), (f32 *)(state + 0x47c), ((SnowBikeState *)state)->collisionFxDamping);
                    PSVECScale((f32 *)(state + 0x494), (f32 *)(state + 0x494), ((SnowBikeState *)state)->collisionFxDamping);
                    ((SnowBikeState *)state)->collisionFxTimer -= timeDelta;
                    if (((SnowBikeState *)state)->collisionFxTimer <= lbl_803E5AE8) {
                        if (Rcp_GetMotionBlurEnabled() != 0) {
                            setMotionBlur(0, lbl_803E5AE8);
                        }
                        ((SnowBikeState *)state)->collisionFxTimer = lbl_803E5AE8;
                    }
                } else {
                    ((SnowBikeState *)state)->unk47C = ((SnowBikeState *)state)->unk464;
                    ((SnowBikeState *)state)->unk480 = ((SnowBikeState *)state)->unk468;
                    ((SnowBikeState *)state)->unk484 = ((SnowBikeState *)state)->unk46C;
                }
                fz = lbl_803E5AE8;
                rq2.quad[1] = fz;
                rq2.quad[2] = fz;
                rq2.quad[3] = fz;
                rq2.quad[0] = lbl_803E5AEC;
                rq2.rot[0] = -((SnowBikeState *)state)->yaw;
                rq2.rot[1] = -((GameObject *)obj)->anim.rotY;
                rq2.rot[2] = -((GameObject *)obj)->anim.rotZ;
                mtxRotateByVec3s(mtx2, rq2.rot);
                Matrix_TransformPoint(mtx2, lbl_803E5AE8, ((SnowBikeState *)state)->unk4B0 * ((SnowBikeState *)state)->unk544, lbl_803E5AE8, &vec2[0], &dummy2, &vec2[2]);
                vec2[0] = vec2[0] * ((SnowBikeState *)state)->unk540;
                vec2[1] = lbl_803E5AE8;
                PSVECScale(vec2, vec2, timeDelta);
                PSVECAdd((f32 *)(state + 0x494), vec2, (f32 *)(state + 0x494));
                ((SnowBikeState *)state)->unk498 = ((SnowBikeState *)state)->unk4B0 * timeDelta + ((SnowBikeState *)state)->unk498;
                p = powfBitEstimate(((SnowBikeState *)state)->unk548, timeDelta);
                ((SnowBikeState *)state)->unk494 *= p;
                p = powfBitEstimate(((SnowBikeState *)state)->unk54C, timeDelta);
                ((SnowBikeState *)state)->unk49C *= p;
                fn_801EC1AC(obj, (int)state);
                Matrix_TransformPoint((f32 *)(state + 0xec), ((SnowBikeState *)state)->unk494, ((SnowBikeState *)state)->unk498, ((SnowBikeState *)state)->unk49C, &((GameObject *)obj)->anim.velocityX, &((GameObject *)obj)->anim.velocityY, &((GameObject *)obj)->anim.velocityZ);
                objApplyVelocity(obj);
            }
            fn_801EB0D4(obj, state);
            fn_801EA240(obj, state, ((SnowBikeState *)state)->unk49C, (int)(lbl_803E5BA0 * -((SnowBikeState *)state)->unk430), state + 0x461, 7);
            fn_801EB634(obj, state);
            *(s16 *)obj = ((SnowBikeState *)state)->yaw;
        }
        break;
    }
}
