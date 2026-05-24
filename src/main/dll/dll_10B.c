#include "ghidra_import.h"
#include "main/dll/dll_10B.h"

extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int curveFn_80010320(double t, int curve);
extern uint randomGetRange(int min, int max);
extern undefined4 ObjHits_SetHitVolumeSlot();
extern int Obj_GetPlayerObject(void);
extern char fn_80296448(int playerObj);
extern void fn_8014C678(double, double, double, int, int *, float *, int);
extern void fn_8014CD1C(double, double, int, int *, int, int);
extern void fn_8014CF7C(double, double, int, int *, int, int);
extern void FUN_80154af4(ushort *obj, int state);
extern void fn_8015536C(double, double, float *, float *);
extern void PSVECSubtract(float *, float *, float *);
extern double PSVECDotProduct(float *, float *);
extern void PSVECCrossProduct(float *, float *, float *);
extern void PSVECNormalize(float *, float *);
extern uint getAngle();
extern void objMove(double, double, double, int);
extern double sqrtf();
extern double fn_80293DA4(double);

extern undefined4 lbl_803DBCD0;
extern undefined4* gRomCurveInterface;
extern f32 timeDelta;
extern f32 lbl_803E2990;
extern f32 lbl_803E2994;
extern f32 lbl_803E29A0;
extern f32 lbl_803E29A4;
extern f64 lbl_803E29A8;
extern f32 lbl_803E29B0;
extern f32 lbl_803E29B4;
extern f32 lbl_803E29BC;
extern f32 lbl_803E29C0;
extern f32 lbl_803E29C4;
extern f64 lbl_803E29C8;
extern f32 lbl_803E29D0;
extern f32 lbl_803E29D4;
extern f64 lbl_803E29D8;
extern f32 lbl_803E29E0;
extern f32 lbl_803E29E4;
extern f32 lbl_803E29E8;
extern f32 lbl_803E29EC;
extern f32 lbl_803E29F0;
extern f32 lbl_803E29F4;
extern f32 lbl_803E29F8;
extern f32 lbl_803E2A00;
extern f32 lbl_803E2A04;
extern f32 lbl_803E2A08;
extern f64 lbl_803E2A10;
extern f64 lbl_803E2A18;

void fn_80154870(int obj, int *state)
{
    float fVar1;
    int iVar2;
    char cVar3;
    int iVar4;
    double dVar5;
    float local_38;
    float local_34;
    float local_30;
    double local_28;
    undefined4 local_20;
    uint uStack_1c;
    double local_18;

    iVar4 = *state;
    if ((state[0xb7] & 0x80000000U) != 0) {
        Sfx_PlayFromObject(obj, 0x4c0);
    }
    if ((((state[0xb7] & 0x2000U) != 0) &&
         (((iVar2 = curveFn_80010320((double)lbl_803E2990, iVar4), iVar2 != 0 ||
            (*(int *)(iVar4 + 0x10) != 0)) &&
           (cVar3 = (**(code **)(*gRomCurveInterface + 0x90))(iVar4), cVar3 != '\0')))) &&
        (cVar3 = (**(code **)(*gRomCurveInterface + 0x8c))
                           ((double)lbl_803E29B0, *state, obj, &lbl_803DBCD0, 0xffffffff),
         cVar3 != '\0')) {
        state[0xb7] = state[0xb7] & 0xffffdfff;
    }
    ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
    cVar3 = fn_80296448(Obj_GetPlayerObject());
    local_38 = *(float *)(state[0xa7] + 0xc) - *(float *)(obj + 0xc);
    local_34 = lbl_803E2990;
    local_30 = *(float *)(state[0xa7] + 0x14) - *(float *)(obj + 0x14);
    if ((state[0xd0] != 0) && (iVar4 = Obj_GetPlayerObject(), state[0xd0] == iVar4)) {
        state[0xb9] = state[0xb9] | 0x10000;
        state[0xc9] = (int)lbl_803E2990;
    }
    local_28 = (double)CONCAT44(0x43300000, (uint)*(byte *)((int)state + 0x33a));
    dVar5 = (double)fn_80293DA4((double)(lbl_803E29C0 * (float)(local_28 - lbl_803E29D8)));
    uStack_1c = (int)*(short *)(obj + 2) ^ 0x80000000;
    local_20 = 0x43300000;
    iVar4 = (int)-(float)((double)lbl_803E29BC * dVar5 -
                          (double)(float)((double)CONCAT44(0x43300000, uStack_1c) - lbl_803E29A8));
    local_18 = (double)(longlong)iVar4;
    *(short *)(obj + 2) = (short)iVar4;
    fVar1 = lbl_803E2990;
    if (cVar3 == '\0') {
        *(float *)(obj + 0x24) = lbl_803E2990;
        *(float *)(obj + 0x2c) = fVar1;
        fn_8014CF7C((double)*(float *)(state[0xa7] + 0xc),
                    (double)*(float *)(state[0xa7] + 0x14), obj, state, 10, 0);
    } else {
        fn_8014C678((double)lbl_803E29A0, (double)lbl_803E29B4,
                    (double)lbl_803E29B4, obj, state, &local_38, 1);
        fn_8014CD1C((double)lbl_803E29C4, (double)lbl_803E2994, obj, state, 0xf, 0);
    }
    fVar1 = lbl_803E2990;
    if ((state[0xb7] & 0x40000000U) != 0) {
        if (lbl_803E2990 == (float)state[0xca]) {
            if (cVar3 == '\0') {
                if (*(float *)(obj + 0x98) <= lbl_803E29A4) {
                    state[0xca] = (int)lbl_803E29E4;
                } else {
                    state[0xca] = (int)lbl_803E29E0;
                    *(char *)((int)state + 0x33b) = *(char *)((int)state + 0x33b) + 1;
                }
            } else if ((double)*(float *)(obj + 0x98) <= lbl_803E29C8) {
                Sfx_PlayFromObject(obj, 0x24c);
                state[0xc2] = (int)lbl_803E29D4;
            } else {
                Sfx_PlayFromObject(obj, 0x24b);
                state[0xc2] = (int)lbl_803E29D0;
            }
        } else {
            state[0xca] = (int)((float)state[0xca] - timeDelta);
            if ((float)state[0xca] <= fVar1) {
                state[0xca] = (int)fVar1;
                if ((double)*(float *)(obj + 0x98) <= lbl_803E29C8) {
                    Sfx_PlayFromObject(obj, 0x24c);
                    state[0xc2] = (int)lbl_803E29B4;
                } else {
                    Sfx_PlayFromObject(obj, 0x24b);
                    state[0xc2] = (int)lbl_803E29D0;
                }
            }
        }
    }
    *(char *)((int)state + 0x33a) = *(char *)((int)state + 0x33a) + 1;
    local_18 = (double)CONCAT44(0x43300000, (uint)*(byte *)((int)state + 0x33a));
    dVar5 = (double)fn_80293DA4((double)(lbl_803E29C0 * (float)(local_18 - lbl_803E29D8)));
    uStack_1c = (int)*(short *)(obj + 2) ^ 0x80000000;
    local_20 = 0x43300000;
    iVar4 = (int)((double)lbl_803E29BC * dVar5 +
                  (double)(float)((double)CONCAT44(0x43300000, uStack_1c) - lbl_803E29A8));
    local_28 = (double)(longlong)iVar4;
    *(short *)(obj + 2) = (short)iVar4;
    FUN_80154af4((ushort *)obj, (int)state);
}

void fn_80154C24(int obj, int state)
{
    float fVar1;
    uint uVar2;

    *(float *)(state + 0x2ac) = lbl_803E29E8;
    *(undefined4 *)(state + 0x2e4) = 0x8000009;
    *(float *)(state + 0x308) = lbl_803E29D0;
    *(float *)(state + 0x300) = lbl_803E29B4;
    *(float *)(state + 0x304) = lbl_803E29EC;
    *(undefined *)(state + 0x320) = 0;
    fVar1 = lbl_803E29F0;
    *(float *)(state + 0x314) = lbl_803E29F0;
    *(undefined *)(state + 0x321) = 1;
    *(float *)(state + 0x318) = lbl_803E2994;
    *(undefined *)(state + 0x322) = 0;
    *(float *)(state + 0x31c) = fVar1;
    fVar1 = lbl_803E2990;
    *(float *)(state + 0x324) = lbl_803E2990;
    *(float *)(state + 0x328) = fVar1;
    *(undefined4 *)(state + 0x32c) = *(undefined4 *)(obj + 0x10);
    uVar2 = randomGetRange(0, 0xff);
    *(char *)(state + 0x33a) = (char)uVar2;
    *(undefined *)(state + 0x33b) = 0;
    *(float *)(state + 0x330) = lbl_803E29F4;
    uVar2 = randomGetRange(0x32, 0x4b);
    *(float *)(state + 0x2fc) = lbl_803E29F8 * (f32)(s32)uVar2;
}

void fn_80154D0C(int obj, int state, undefined2 *outAngle, float *outDistance)
{
    int targetObj;
    uint angle;
    double objPlane;
    double objY;
    double targetPlane;
    double targetY;
    float local_b8;
    float local_b4;
    float local_b0;
    float local_ac;
    float local_a8;
    float local_a4;
    float local_a0[2];
    float local_98;
    float local_94;
    float local_90;
    float local_8c;
    float targetToPlane[3];
    float local_7c[2];
    float local_74;
    float local_70;
    float local_6c;
    float local_68;
    float objToPlane[3];
    float targetPos[3];

    local_70 = *(float *)(state + 0x360);
    local_6c = *(float *)(state + 0x358);
    local_68 = *(float *)(state + 0x364);
    PSVECSubtract(&local_70, (float *)(obj + 0xc), objToPlane);
    objPlane = (double)PSVECDotProduct(objToPlane, (float *)(state + 0x344));
    local_70 = (float)((double)*(float *)(state + 0x344) * objPlane + (double)*(float *)(obj + 0xc));
    objY = (double)*(float *)(obj + 0x10);
    local_6c = (float)((double)*(float *)(state + 0x348) * objPlane + objY);
    local_68 = (float)((double)*(float *)(state + 0x34c) * objPlane + (double)*(float *)(obj + 0x14));
    local_ac = lbl_803E2A00;
    local_a8 = lbl_803E2A04;
    local_a4 = lbl_803E2A00;
    PSVECCrossProduct(&local_ac, (float *)(state + 0x344), local_7c);
    PSVECNormalize(local_7c, local_7c);
    if (lbl_803E2A00 == local_7c[0]) {
        local_7c[0] = (*(float *)(obj + 0x14) - *(float *)(state + 0x364)) / local_74;
    } else {
        local_7c[0] = (*(float *)(obj + 0xc) - *(float *)(state + 0x360)) / local_7c[0];
    }
    targetPlane = (double)local_7c[0];
    targetObj = *(int *)(state + 0x29c);
    targetPos[0] = *(float *)(targetObj + 0xc);
    targetPos[1] = lbl_803E2A08 + *(float *)(targetObj + 0x10);
    targetPos[2] = *(float *)(targetObj + 0x14);
    local_94 = *(float *)(state + 0x360);
    local_90 = *(float *)(state + 0x358);
    local_8c = *(float *)(state + 0x364);
    PSVECSubtract(&local_94, targetPos, targetToPlane);
    objPlane = (double)PSVECDotProduct(targetToPlane, (float *)(state + 0x344));
    local_94 = (float)((double)*(float *)(state + 0x344) * objPlane + (double)targetPos[0]);
    targetY = (double)targetPos[1];
    local_90 = (float)((double)*(float *)(state + 0x348) * objPlane + targetY);
    local_8c = (float)((double)*(float *)(state + 0x34c) * objPlane + (double)targetPos[2]);
    local_b8 = lbl_803E2A00;
    local_b4 = lbl_803E2A04;
    local_b0 = lbl_803E2A00;
    PSVECCrossProduct(&local_b8, (float *)(state + 0x344), local_a0);
    PSVECNormalize(local_a0, local_a0);
    if (lbl_803E2A00 == local_a0[0]) {
        local_a0[0] = (targetPos[2] - *(float *)(state + 0x364)) / local_98;
    } else {
        local_a0[0] = (targetPos[0] - *(float *)(state + 0x360)) / local_a0[0];
    }
    targetPlane = (double)(float)(targetPlane - (double)local_a0[0]);
    objPlane = (double)(float)(objY - targetY);
    angle = getAngle(-objPlane, targetPlane);
    targetObj = (angle & 0xffff) - ((int)*(short *)(obj + 2) & 0xffffU);
    if (0x8000 < targetObj) {
        targetObj = targetObj - 0xffff;
    }
    if (targetObj < -0x8000) {
        targetObj = targetObj + 0xffff;
    }
    if (targetObj < 0) {
        targetObj = -targetObj;
    }
    *outAngle = (short)targetObj;
    objPlane = (double)sqrtf((double)(float)(targetPlane * targetPlane +
                                            (double)(float)(objPlane * objPlane)));
    *outDistance = (float)objPlane;
}

uint fn_80154FB4(double maxDistance, short *obj, int state, uint turnTime)
{
    float fVar1;
    int iVar2;
    uint angleStep;
    short sVar4;
    double objPlane;
    double objY;
    double targetPlane;
    double targetY;
    double distance;
    float local_108;
    float local_104;
    float local_100;
    float local_fc;
    float local_f8;
    float local_f4;
    float local_f0[2];
    float local_e8;
    float local_e4;
    float local_e0;
    float local_dc;
    float targetToPlane[3];
    float local_cc[2];
    float local_c4;
    float local_c0;
    float local_bc;
    float local_b8;
    float objToPlane[3];
    float targetPos[3];
    float moveTarget[3];
    undefined4 local_80;
    uint uStack_7c;
    undefined4 local_78;
    uint uStack_74;
    longlong local_70;

    local_c0 = *(float *)(state + 0x360);
    local_bc = *(float *)(state + 0x358);
    local_b8 = *(float *)(state + 0x364);
    PSVECSubtract(&local_c0, (float *)(obj + 6), objToPlane);
    objPlane = (double)PSVECDotProduct(objToPlane, (float *)(state + 0x344));
    local_c0 = (float)((double)*(float *)(state + 0x344) * objPlane + (double)*(float *)(obj + 6));
    objY = (double)*(float *)(obj + 8);
    local_bc = (float)((double)*(float *)(state + 0x348) * objPlane + objY);
    local_b8 = (float)((double)*(float *)(state + 0x34c) * objPlane + (double)*(float *)(obj + 10));
    local_fc = lbl_803E2A00;
    local_f8 = lbl_803E2A04;
    local_f4 = lbl_803E2A00;
    PSVECCrossProduct(&local_fc, (float *)(state + 0x344), local_cc);
    PSVECNormalize(local_cc, local_cc);
    if (lbl_803E2A00 == local_cc[0]) {
        local_cc[0] = (*(float *)(obj + 10) - *(float *)(state + 0x364)) / local_c4;
    } else {
        local_cc[0] = (*(float *)(obj + 6) - *(float *)(state + 0x360)) / local_cc[0];
    }
    targetPlane = (double)local_cc[0];
    iVar2 = *(int *)(state + 0x29c);
    targetPos[0] = *(float *)(iVar2 + 0xc);
    targetPos[1] = lbl_803E2A08 + *(float *)(iVar2 + 0x10);
    targetPos[2] = *(float *)(iVar2 + 0x14);
    local_e4 = *(float *)(state + 0x360);
    local_e0 = *(float *)(state + 0x358);
    local_dc = *(float *)(state + 0x364);
    PSVECSubtract(&local_e4, targetPos, targetToPlane);
    objPlane = (double)PSVECDotProduct(targetToPlane, (float *)(state + 0x344));
    local_e4 = (float)((double)*(float *)(state + 0x344) * objPlane + (double)targetPos[0]);
    targetY = (double)targetPos[1];
    local_e0 = (float)((double)*(float *)(state + 0x348) * objPlane + targetY);
    local_dc = (float)((double)*(float *)(state + 0x34c) * objPlane + (double)targetPos[2]);
    local_108 = lbl_803E2A00;
    local_104 = lbl_803E2A04;
    local_100 = lbl_803E2A00;
    PSVECCrossProduct(&local_108, (float *)(state + 0x344), local_f0);
    PSVECNormalize(local_f0, local_f0);
    if (lbl_803E2A00 == local_f0[0]) {
        local_f0[0] = (targetPos[2] - *(float *)(state + 0x364)) / local_e8;
    } else {
        local_f0[0] = (targetPos[0] - *(float *)(state + 0x360)) / local_f0[0];
    }
    objPlane = (double)(float)(targetPlane - (double)local_f0[0]);
    targetY = (double)(float)(objY - targetY);
    angleStep = getAngle(-targetY, objPlane);
    uStack_74 = (angleStep & 0xffff) - ((int)obj[1] & 0xffffU);
    if (0x8000 < (int)uStack_74) {
        uStack_74 = uStack_74 - 0xffff;
    }
    if ((int)uStack_74 < -0x8000) {
        uStack_74 = uStack_74 + 0xffff;
    }
    uStack_7c = turnTime & 0xffff;
    local_80 = 0x43300000;
    fVar1 = timeDelta / (float)((double)CONCAT44(0x43300000, uStack_7c) - lbl_803E2A10);
    if (lbl_803E2A04 < fVar1) {
        fVar1 = lbl_803E2A04;
    }
    uStack_74 = uStack_74 ^ 0x80000000;
    local_78 = 0x43300000;
    angleStep = (uint)((float)((double)CONCAT44(0x43300000, uStack_74) - lbl_803E2A18) * fVar1);
    local_70 = (longlong)(int)angleStep;
    *obj = obj[1] + (short)angleStep;
    obj[2] = 0x4000;
    obj[1] = *obj;
    sVar4 = getAngle((double)*(float *)(state + 0x34c), -(double)*(float *)(state + 0x344));
    *obj = sVar4;
    distance = (double)sqrtf((double)(float)(objPlane * objPlane +
                                            (double)(float)(targetY * targetY)));
    if (maxDistance < distance) {
        objPlane = (double)(float)(maxDistance *
                                   (double)(float)(objPlane *
                                                   (double)(float)((double)lbl_803E2A04 / distance)));
        targetY = (double)(float)(maxDistance *
                                  (double)(float)(targetY *
                                                  (double)(float)((double)lbl_803E2A04 / distance)));
    }
    fn_8015536C((double)(float)(targetPlane - objPlane), (double)(float)(objY - targetY),
                moveTarget, (float *)(state + 0x344));
    PSVECSubtract(moveTarget, (float *)(obj + 6), targetPos);
    objMove((double)targetPos[0], (double)targetPos[1], (double)targetPos[2], (int)obj);
    fVar1 = lbl_803E2A00;
    *(float *)(obj + 0x12) = lbl_803E2A00;
    *(float *)(obj + 0x14) = fVar1;
    *(float *)(obj + 0x16) = fVar1;
    if ((int)angleStep < 0) {
        angleStep = -angleStep;
    }
    return angleStep & 0xffff;
}
