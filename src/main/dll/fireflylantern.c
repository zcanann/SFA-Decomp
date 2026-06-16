#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"


extern int Curve_AdvanceAlongPath(RomCurveWalker *curve, f32 t);
extern uint randomGetRange(int min, int max);
extern int Obj_GetPlayerObject(void);
extern char fn_80296448(int playerObj);
extern void fn_8014C678(int obj, int* state, f32* vec, f32 a, f32 b, f32 c, int d);
extern void fn_8014CD1C(int obj, int* state, int a, f32 x, f32 y, int b);
extern void fn_8014CF7C(int obj, int* state, f32 x, f32 z, int a, int b);
extern void fn_80154328(int obj, int* state);
extern void fn_8015536C(f32* out, f32* axis, f32 a, f32 b);
extern void PSVECSubtract(float*, float*, float*);
extern f32 PSVECDotProduct(float*, float*);
extern void PSVECCrossProduct(float*, float*, float*);
extern void PSVECNormalize(float*, float*);
extern uint getAngle(f32, f32);
extern void objMove(short* obj, f32 x, f32 y, f32 z);
extern f32 sqrtf(f32);
extern f32 fn_80293DA4(f32);

extern undefined4 lbl_803DBCD0;
extern f32 timeDelta;
extern f32 lbl_803E2990;
extern f32 lbl_803E2994;
extern f32 lbl_803E29A0;
extern f32 lbl_803E29A4;
extern f32 lbl_803E29B0;
extern f32 lbl_803E29B4;
extern f32 lbl_803E29BC;
extern f32 lbl_803E29C0;
extern f32 lbl_803E29C4;
extern f64 lbl_803E29C8;
extern f32 lbl_803E29D0;
extern f32 lbl_803E29D4;
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

void fn_80154870(int obj, int* state)
{
    RomCurveWalker* curve;
    u8 flag;
    f32 dvec[3];
    f32 fval;

    curve = (RomCurveWalker*)*state;
    if (state[0xb7] & 0x80000000U)
    {
        Sfx_PlayFromObject((u32)obj, 0x4c0);
    }
    if (((state[0xb7] & 0x2000U) != 0) &&
        ((Curve_AdvanceAlongPath(curve, lbl_803E2990) != 0 || curve->atSegmentEnd != 0) &&
            ((*gRomCurveInterface)->goNextPoint(curve) != 0)) &&
        ((*gRomCurveInterface)->initCurve(curve, (void*)obj, lbl_803E29B0,
                                          (int*)&lbl_803DBCD0, -1) != 0))
    {
        *(u32*)&state[0xb7] &= ~0x2000LL;
    }
    ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
    flag = fn_80296448(Obj_GetPlayerObject());
    dvec[0] = *(f32*)(state[0xa7] + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dvec[1] = lbl_803E2990;
    dvec[2] = *(f32*)(state[0xa7] + 0x14) - ((GameObject*)obj)->anim.localPosZ;
    if (((u32)state[0xd0] != 0) && ((u32)state[0xd0] == (u32)Obj_GetPlayerObject()))
    {
        *(u32*)&state[0xb9] |= 0x10000LL;
        *(f32*)(state + 0xc9) = lbl_803E2990;
    }
    ((GameObject*)obj)->anim.rotY =
        -(lbl_803E29BC * fn_80293DA4(lbl_803E29C0 * (f32)(u32) * (u8*)((u8*)state + 0x33a)) -
            (f32)((GameObject*)obj)->anim.rotY);
    if (flag == 0)
    {
        fval = lbl_803E2990;
        ((GameObject*)obj)->anim.velocityX = fval;
        ((GameObject*)obj)->anim.velocityZ = fval;
        fn_8014CF7C(obj, state, *(f32*)(state[0xa7] + 0xc), *(f32*)(state[0xa7] + 0x14), 10, 0);
    }
    else
    {
        fn_8014C678(obj, state, dvec, lbl_803E29A0, lbl_803E29B4, *(f32*)&lbl_803E29B4, 1);
        fn_8014CD1C(obj, state, 0xf, lbl_803E29C4, lbl_803E2994, 0);
    }
    if (state[0xb7] & 0x40000000U)
    {
        fval = *(f32*)&lbl_803E2990;
        if (fval == *(f32*)(state + 0xca))
        {
            if (flag == 0)
            {
                if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E29A4)
                {
                    *(f32*)(state + 0xca) = lbl_803E29E0;
                    *(u8*)((u8*)state + 0x33b) += 1;
                }
                else
                {
                    *(f32*)(state + 0xca) = lbl_803E29E4;
                }
            }
            else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E29C8)
            {
                Sfx_PlayFromObject((u32)obj, SFXfox_fightbreath1);
                *(f32*)(state + 0xc2) = lbl_803E29D0;
            }
            else
            {
                Sfx_PlayFromObject((u32)obj, SFXfox_fightbreath2);
                *(f32*)(state + 0xc2) = lbl_803E29D4;
            }
        }
        else
        {
            *(f32*)(state + 0xca) = *(f32*)(state + 0xca) - timeDelta;
            if (*(f32*)(state + 0xca) <= fval)
            {
                *(f32*)(state + 0xca) = fval;
                if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E29C8)
                {
                    Sfx_PlayFromObject((u32)obj, SFXfox_fightbreath1);
                    *(f32*)(state + 0xc2) = lbl_803E29D0;
                }
                else
                {
                    Sfx_PlayFromObject((u32)obj, SFXfox_fightbreath2);
                    *(f32*)(state + 0xc2) = lbl_803E29B4;
                }
            }
        }
    }
    *(u8*)((u8*)state + 0x33a) += 1;
    ((GameObject*)obj)->anim.rotY =
    (lbl_803E29BC * fn_80293DA4(lbl_803E29C0 * (f32)(u32) * (u8*)((u8*)state + 0x33a)) +
        (f32)((GameObject*)obj)->anim.rotY);
    fn_80154328(obj, state);
}

void fn_80154C24(int obj, int state)
{
    float fval;
    uint randVal;

    ((BaddieState*)state)->speedScale = lbl_803E29E8;
    ((BaddieState*)state)->unk2E4 = 0x8000009;
    ((BaddieState*)state)->unk308 = lbl_803E29D0;
    ((BaddieState*)state)->unk300 = lbl_803E29B4;
    ((BaddieState*)state)->unk304 = lbl_803E29EC;
    ((BaddieState*)state)->unk320 = 0;
    fval = lbl_803E29F0;
    *(float*)(state + 0x314) = lbl_803E29F0;
    ((BaddieState*)state)->unk321 = 1;
    ((BaddieState*)state)->unk318 = lbl_803E2994;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fval;
    fval = lbl_803E2990;
    *(float*)(state + 0x324) = lbl_803E2990;
    *(float*)(state + 0x328) = fval;
    *(float*)(state + 0x32c) = ((GameObject*)obj)->anim.localPosY;
    randVal = randomGetRange(0, 0xff);
    *(u8*)(state + 0x33a) = randVal;
    *(undefined*)(state + 0x33b) = 0;
    *(float*)(state + 0x330) = lbl_803E29F4;
    randVal = randomGetRange(0x32, 0x4b);
    fval = (f32)(s32)
    randVal;
    fval = lbl_803E29F8 * fval;
    ((BaddieState*)state)->pathStep = fval;
}

void fn_80154D0C(int obj, int state, u16* outAngle, float* outDistance)
{
    f32 targetPos[3];
    f32 tmpA[3];
    f32 vecA[3];
    f32 crossA[3];
    f32 tmpB[3];
    f32 vecB[3];
    f32 crossB[3];
    f32 axisA[3];
    f32 axisB[3];
    f32 objY;
    f32 dx;
    f32 targetY;
    f32 d;
    int targetObj;
    int delta;
    uint angle;

    vecA[0] = *(f32*)(state + 0x360);
    vecA[1] = *(f32*)(state + 0x358);
    vecA[2] = *(f32*)(state + 0x364);
    PSVECSubtract(vecA, (f32*)(obj + 0xc), tmpA);
    d = PSVECDotProduct(tmpA, (f32*)(state + 0x344));
    vecA[0] = *(f32*)(state + 0x344) * d + ((GameObject*)obj)->anim.localPosX;
    vecA[1] = *(f32*)(state + 0x348) * d + (objY = ((GameObject*)obj)->anim.localPosY);
    vecA[2] = *(f32*)(state + 0x34c) * d + ((GameObject*)obj)->anim.localPosZ;
    axisA[0] = lbl_803E2A00;
    axisA[1] = lbl_803E2A04;
    axisA[2] = lbl_803E2A00;
    PSVECCrossProduct(axisA, (f32*)(state + 0x344), crossA);
    PSVECNormalize(crossA, crossA);
    if (lbl_803E2A00 != crossA[0])
    {
        dx = (((GameObject*)obj)->anim.localPosX - *(f32*)(state + 0x360)) / crossA[0];
    }
    else
    {
        dx = (((GameObject*)obj)->anim.localPosZ - *(f32*)(state + 0x364)) / crossA[2];
    }
    targetObj = *(int*)&((BaddieState*)state)->trackedObj;
    targetPos[0] = *(f32*)(targetObj + 0xc);
    targetPos[1] = lbl_803E2A08 + *(f32*)(targetObj + 0x10);
    targetPos[2] = *(f32*)(targetObj + 0x14);
    vecB[0] = *(f32*)(state + 0x360);
    vecB[1] = *(f32*)(state + 0x358);
    vecB[2] = *(f32*)(state + 0x364);
    PSVECSubtract(vecB, targetPos, tmpB);
    d = PSVECDotProduct(tmpB, (f32*)(state + 0x344));
    vecB[0] = *(f32*)(state + 0x344) * d + targetPos[0];
    vecB[1] = *(f32*)(state + 0x348) * d + (targetY = targetPos[1]);
    vecB[2] = *(f32*)(state + 0x34c) * d + targetPos[2];
    axisB[0] = lbl_803E2A00;
    axisB[1] = lbl_803E2A04;
    axisB[2] = lbl_803E2A00;
    PSVECCrossProduct(axisB, (f32*)(state + 0x344), crossB);
    PSVECNormalize(crossB, crossB);
    if (lbl_803E2A00 != crossB[0])
    {
        d = (targetPos[0] - *(f32*)(state + 0x360)) / crossB[0];
    }
    else
    {
        d = (targetPos[2] - *(f32*)(state + 0x364)) / crossB[2];
    }
    dx = dx - d;
    targetY = objY - targetY;
    angle = getAngle(-targetY, dx) & 0xffff;
    delta = angle - (((GameObject*)obj)->anim.rotY & 0xffff);
    if (delta > 0x8000)
    {
        delta = delta - 0xffff;
    }
    if (delta < -0x8000)
    {
        delta = delta + 0xffff;
    }
    if (delta < 0)
    {
        delta = -delta;
    }
    *outAngle = delta & 0xffff;
    *outDistance = sqrtf(dx * dx + targetY * targetY);
}

uint fn_80154FB4(short* obj, int state, uint turnTime, f32 maxDistance)
{
    f32 moveTarget[3];
    f32 moveDelta[3];
    f32 targetPos[3];
    f32 tmpA[3];
    f32 vecA[3];
    f32 crossA[3];
    f32 tmpB[3];
    f32 vecB[3];
    f32 crossB[3];
    f32 axisA[3];
    f32 axisB[3];
    f32 objY;
    f32 targetY;
    f32 dy;
    f32 dxA;
    f32 dxDiff;
    f32 d;
    f32 turnStep;
    s16 rot;
    int curve;
    int delta;
    int angleStep;
    uint angle;

    vecA[0] = *(f32*)(state + 0x360);
    vecA[1] = *(f32*)(state + 0x358);
    vecA[2] = *(f32*)(state + 0x364);
    PSVECSubtract(vecA, (f32*)(obj + 6), tmpA);
    d = PSVECDotProduct(tmpA, (f32*)(state + 0x344));
    vecA[0] = *(f32*)(state + 0x344) * d + ((GameObject*)obj)->anim.localPosX;
    vecA[1] = *(f32*)(state + 0x348) * d + (objY = ((GameObject*)obj)->anim.localPosY);
    vecA[2] = *(f32*)(state + 0x34c) * d + ((GameObject*)obj)->anim.localPosZ;
    axisA[0] = lbl_803E2A00;
    axisA[1] = lbl_803E2A04;
    axisA[2] = lbl_803E2A00;
    PSVECCrossProduct(axisA, (f32*)(state + 0x344), crossA);
    PSVECNormalize(crossA, crossA);
    if (lbl_803E2A00 != crossA[0])
    {
        dxA = (((GameObject*)obj)->anim.localPosX - *(f32*)(state + 0x360)) / crossA[0];
    }
    else
    {
        dxA = (((GameObject*)obj)->anim.localPosZ - *(f32*)(state + 0x364)) / crossA[2];
    }
    curve = *(int*)&((BaddieState*)state)->trackedObj;
    targetPos[0] = *(f32*)(curve + 0xc);
    targetPos[1] = lbl_803E2A08 + *(f32*)(curve + 0x10);
    targetPos[2] = *(f32*)(curve + 0x14);
    vecB[0] = *(f32*)(state + 0x360);
    vecB[1] = *(f32*)(state + 0x358);
    vecB[2] = *(f32*)(state + 0x364);
    PSVECSubtract(vecB, targetPos, tmpB);
    d = PSVECDotProduct(tmpB, (f32*)(state + 0x344));
    vecB[0] = *(f32*)(state + 0x344) * d + targetPos[0];
    vecB[1] = *(f32*)(state + 0x348) * d + (targetY = targetPos[1]);
    vecB[2] = *(f32*)(state + 0x34c) * d + targetPos[2];
    axisB[0] = lbl_803E2A00;
    axisB[1] = lbl_803E2A04;
    axisB[2] = lbl_803E2A00;
    PSVECCrossProduct(axisB, (f32*)(state + 0x344), crossB);
    PSVECNormalize(crossB, crossB);
    if (lbl_803E2A00 != crossB[0])
    {
        d = (targetPos[0] - *(f32*)(state + 0x360)) / crossB[0];
    }
    else
    {
        d = (targetPos[2] - *(f32*)(state + 0x364)) / crossB[2];
    }
    dxDiff = dxA - d;
    dy = objY - targetY;
    angle = getAngle(-dy, dxDiff) & 0xffff;
    rot = ((GameObject*)obj)->anim.rotY;
    delta = angle - (rot & 0xffff);
    if (delta > 0x8000)
    {
        delta = delta - 0xffff;
    }
    if (delta < -0x8000)
    {
        delta = delta + 0xffff;
    }
    turnStep = timeDelta / (f32)(turnTime & 0xffff);
    if (turnStep > lbl_803E2A04)
    {
        turnStep = lbl_803E2A04;
    }
    angleStep = (int)((f32)delta * turnStep);
    *obj = (s16)(rot + angleStep);
    ((GameObject*)obj)->anim.rotZ = 0x4000;
    ((GameObject*)obj)->anim.rotY = *obj;
    *obj = (s16)getAngle(*(f32*)(state + 0x34c), -*(f32*)(state + 0x344));
    turnStep = sqrtf(dxDiff * dxDiff + dy * dy);
    if (turnStep > maxDistance)
    {
        f32 ratio = lbl_803E2A04 / turnStep;
        dxDiff = maxDistance * (dxDiff * ratio);
        dy = maxDistance * (dy * ratio);
    }
    dxA -= dxDiff;
    turnStep = objY - dy;
    fn_8015536C(moveTarget, (f32*)(state + 0x344), dxA, turnStep);
    PSVECSubtract(moveTarget, (f32*)(obj + 6), moveDelta);
    objMove(obj, moveDelta[0], moveDelta[1], moveDelta[2]);
    turnStep = lbl_803E2A00;
    ((GameObject*)obj)->anim.velocityX = turnStep;
    ((GameObject*)obj)->anim.velocityY = turnStep;
    ((GameObject*)obj)->anim.velocityZ = turnStep;
    if (angleStep < 0)
    {
        angleStep = -angleStep;
    }
    return angleStep & 0xffff;
}

