/*
 * fireflylantern - named for the firefly-lantern DLL object whose source
 * this TU was split from; it owns the generic rom-curve path-walk and
 * target-steering helpers that object first defined, which the fox-fighting
 * baddie family then reuses (the "fox fightbreath" SFX and BaddieState
 * path/curve fields identify the latter). These four routines live in this
 * object but are linked into sibling baddie DLLs:
 *   - fn_80154870  per-frame update: walks the rom curve path, faces the
 *     player, drives the move/look helpers and plays attack-breath SFX.
 *   - fn_80154C24  state init: seeds BaddieState path/speed fields and a
 *     random path phase/step.
 *   - fn_80154D0C  computes the signed angle + planar distance from the
 *     object to its tracked target relative to the path plane.
 *   - fn_80154FB4  steers/moves the object toward its target along the
 *     path plane, clamped by a per-frame turn rate and max step.
 * (callers: dll_00C9_enemy, duster.)
 */
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"

extern int randomGetRange(int lo, int hi);
extern int Obj_GetPlayerObject(void);
extern int fn_80296448(int obj);
extern void fn_8014C678(int obj, int* state, f32* vec, f32 a, f32 b, f32 c, int d);
extern void fn_8014CD1C(int obj, int* state, int a, f32 x, f32 y, int b);
extern void fn_8014CF7C(int obj, int* state, f32 x, f32 z, int a, int b);
extern void fn_80154328(int obj, int* state);
extern void fn_8015536C(f32* out, f32* axis, f32 a, f32 b);
extern void PSVECSubtract(float*, float*, float*);
extern f32 PSVECDotProduct(float*, float*);
extern void PSVECCrossProduct(float*, float*, float*);
extern void PSVECNormalize(float*, float*);
extern int getAngle(float y, float x);
extern void objMove(short* obj, f32 x, f32 y, f32 z);
extern f32 sqrtf(f32);
extern u32 lbl_803DBCD0;
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
extern f32 gFireflyLanternPathStepScale;
extern f32 lbl_803E2A00;
extern f32 lbl_803E2A04;
extern f32 lbl_803E2A08;

/*
 * FireflyState - file-local overlay naming the PER-FAMILY scratch that
 * baddie_state.h leaves raw for this path-walking baddie:
 *  - trackTimer(0x324): reset to 0 while facing the tracked player.
 *  - breathTimer(0x328): fightbreath-SFX cooldown, counts down by timeDelta.
 *  - anchorY(0x32C): object localPosY captured at init.
 *  - unk330(0x330): init-seeded f32 constant.
 */
typedef struct FireflyState {
    u8 pad00[0x324];
    f32 trackTimer;   /* 0x324 */
    f32 breathTimer;  /* 0x328 */
    f32 anchorY;      /* 0x32C */
    f32 unk330;       /* 0x330 */
    u8 pad334[0x358 - 0x334];
    /* 0x344..0x364 is the wall/plane block fn_801554B4 (duster.c) writes.
     * planeNormal (0x344..0x34C) is passed by address to the PSVEC helpers,
     * so it stays raw here; only the scalar-only anchor point is named. */
    f32 planeAnchorY; /* 0x358 */
    u8 pad35C[0x360 - 0x35C];
    f32 planeAnchorX; /* 0x360 */
    f32 planeAnchorZ; /* 0x364 */
} FireflyState;

#pragma opt_common_subs off
void fn_80154870(int obj, int* state)
{
    RomCurveWalker* curve;
    u8 flag;
    f32 dvec[3];
    f32 fval;

    curve = (RomCurveWalker*)*state;
    if (state[0xb7] & 0x80000000U)
    {
        Sfx_PlayFromObject((u32)obj, SFXTRIG_windlift_loop);
    }
    if (((state[0xb7] & 0x2000U) != 0) &&
        ((Curve_AdvanceAlongPath(curve, lbl_803E2990) != 0 || curve->atSegmentEnd != 0) &&
            ((*gRomCurveInterface)->goNextPoint(curve) != 0)) &&
        ((*gRomCurveInterface)->initCurve((RomCurveWalker*)*state, (void*)obj, lbl_803E29B0,
                                          (int*)&lbl_803DBCD0, -1) != 0))
    {
        *(u32*)&state[0xb7] &= ~0x2000LL;
    }
    ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
    flag = fn_80296448(Obj_GetPlayerObject());
    dvec[0] = *(f32*)(state[0xa7] + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dvec[1] = lbl_803E2990;
    dvec[2] = *(f32*)(state[0xa7] + 0x14) - ((GameObject*)obj)->anim.localPosZ;
    if (((u32)state[0xd0] != 0) && ((u32)state[0xd0] == Obj_GetPlayerObject()))
    {
        *(u32*)&state[0xb9] |= 0x10000LL;
        ((FireflyState*)state)->trackTimer = lbl_803E2990;
    }
    ((GameObject*)obj)->anim.rotY =
        -(lbl_803E29BC * fn_80293DA4(lbl_803E29C0 * (f32)(u32)((BaddieState*)state)->seqEntryIndex) -
            (f32)((GameObject*)obj)->anim.rotY);
    if (flag == 0)
    {
        fval = lbl_803E2990;
        ((GameObject*)obj)->anim.velocityX = fval;
        ((GameObject*)obj)->anim.velocityZ = fval;
        curve = (RomCurveWalker*)state[0xa7];
        fn_8014CF7C(obj, state, *(f32*)((u8*)curve + 0xc), *(f32*)((u8*)curve + 0x14), 10, 0);
    }
    else
    {
        fn_8014C678(obj, state, dvec, lbl_803E29A0, lbl_803E29B4, *(f32*)&lbl_803E29B4, 1);
        fn_8014CD1C(obj, state, 0xf, lbl_803E29C4, lbl_803E2994, 0);
    }
    if (state[0xb7] & 0x40000000U)
    {
        fval = *(f32*)&lbl_803E2990;
        if (fval == ((FireflyState*)state)->breathTimer)
        {
            if (flag == 0)
            {
                if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E29A4)
                {
                    ((FireflyState*)state)->breathTimer = lbl_803E29E0;
                    ((BaddieState*)state)->inWhirlpoolGroup += 1;
                }
                else
                {
                    ((FireflyState*)state)->breathTimer = lbl_803E29E4;
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
            ((FireflyState*)state)->breathTimer = ((FireflyState*)state)->breathTimer - timeDelta;
            if (((FireflyState*)state)->breathTimer <= fval)
            {
                ((FireflyState*)state)->breathTimer = fval;
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
    ((BaddieState*)state)->seqEntryIndex += 1;
    ((GameObject*)obj)->anim.rotY =
    (lbl_803E29BC * fn_80293DA4(lbl_803E29C0 * (f32)(u32)((BaddieState*)state)->seqEntryIndex) +
        (f32)((GameObject*)obj)->anim.rotY);
    fn_80154328(obj, state);
}
#pragma opt_common_subs reset


void fn_80154C24(int obj, int state)
{
    float fval;
    u32 randVal;

    ((BaddieState*)state)->speedScale = lbl_803E29E8;
    ((BaddieState*)state)->unk2E4 = 0x8000009;
    ((BaddieState*)state)->unk308 = lbl_803E29D0;
    ((BaddieState*)state)->animDeltaScale = lbl_803E29B4;
    ((BaddieState*)state)->unk304 = lbl_803E29EC;
    ((BaddieState*)state)->unk320 = 0;
    fval = lbl_803E29F0;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E29F0;
    ((BaddieState*)state)->unk321 = 1;
    ((BaddieState*)state)->unk318 = lbl_803E2994;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fval;
    fval = lbl_803E2990;
    ((FireflyState*)state)->trackTimer = fval;
    ((FireflyState*)state)->breathTimer = fval;
    ((FireflyState*)state)->anchorY = ((GameObject*)obj)->anim.localPosY;
    randVal = randomGetRange(0, 0xff);
    ((BaddieState*)state)->seqEntryIndex = randVal;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    ((FireflyState*)state)->unk330 = lbl_803E29F4;
    randVal = randomGetRange(0x32, 0x4b);
    fval = (f32)(s32)randVal;
    fval = gFireflyLanternPathStepScale * fval;
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
    f32 dxDiff;
    f32 dy;
    f32 d;
    int targetObj;
    int delta;
    u32 angle;

    vecA[0] = ((FireflyState*)state)->planeAnchorX;
    vecA[1] = ((FireflyState*)state)->planeAnchorY;
    vecA[2] = ((FireflyState*)state)->planeAnchorZ;
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
        dxDiff = (((GameObject*)obj)->anim.localPosX - ((FireflyState*)state)->planeAnchorX) / crossA[0];
    }
    else
    {
        dxDiff = (((GameObject*)obj)->anim.localPosZ - ((FireflyState*)state)->planeAnchorZ) / crossA[2];
    }
    targetObj = *(int*)&((BaddieState*)state)->trackedObj;
    targetPos[0] = ((GameObject*)targetObj)->anim.localPosX;
    targetPos[1] = lbl_803E2A08 + ((GameObject*)targetObj)->anim.localPosY;
    targetPos[2] = ((GameObject*)targetObj)->anim.localPosZ;
    vecB[0] = ((FireflyState*)state)->planeAnchorX;
    vecB[1] = ((FireflyState*)state)->planeAnchorY;
    vecB[2] = ((FireflyState*)state)->planeAnchorZ;
    PSVECSubtract(vecB, targetPos, tmpB);
    d = PSVECDotProduct(tmpB, (f32*)(state + 0x344));
    vecB[0] = *(f32*)(state + 0x344) * d + targetPos[0];
    vecB[1] = *(f32*)(state + 0x348) * d + (dy = targetPos[1]);
    vecB[2] = *(f32*)(state + 0x34c) * d + targetPos[2];
    axisB[0] = lbl_803E2A00;
    axisB[1] = lbl_803E2A04;
    axisB[2] = lbl_803E2A00;
    PSVECCrossProduct(axisB, (f32*)(state + 0x344), crossB);
    PSVECNormalize(crossB, crossB);
    if (lbl_803E2A00 != crossB[0])
    {
        d = (targetPos[0] - ((FireflyState*)state)->planeAnchorX) / crossB[0];
    }
    else
    {
        d = (targetPos[2] - ((FireflyState*)state)->planeAnchorZ) / crossB[2];
    }
    dxDiff = dxDiff - d;
    dy = objY - dy;
    angle = getAngle(-dy, dxDiff) & 0xffff;
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
    *outDistance = sqrtf(dxDiff * dxDiff + dy * dy);
}

u32 fn_80154FB4(short* obj, int state, u32 turnTime, f32 maxDistance)
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
    int targetObj;
    int delta;
    int angleStep;
    u32 angle;

    vecA[0] = ((FireflyState*)state)->planeAnchorX;
    vecA[1] = ((FireflyState*)state)->planeAnchorY;
    vecA[2] = ((FireflyState*)state)->planeAnchorZ;
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
        dxA = (((GameObject*)obj)->anim.localPosX - ((FireflyState*)state)->planeAnchorX) / crossA[0];
    }
    else
    {
        dxA = (((GameObject*)obj)->anim.localPosZ - ((FireflyState*)state)->planeAnchorZ) / crossA[2];
    }
    targetObj = *(int*)&((BaddieState*)state)->trackedObj;
    targetPos[0] = ((GameObject*)targetObj)->anim.localPosX;
    targetPos[1] = lbl_803E2A08 + ((GameObject*)targetObj)->anim.localPosY;
    targetPos[2] = ((GameObject*)targetObj)->anim.localPosZ;
    vecB[0] = ((FireflyState*)state)->planeAnchorX;
    vecB[1] = ((FireflyState*)state)->planeAnchorY;
    vecB[2] = ((FireflyState*)state)->planeAnchorZ;
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
        d = (targetPos[0] - ((FireflyState*)state)->planeAnchorX) / crossB[0];
    }
    else
    {
        d = (targetPos[2] - ((FireflyState*)state)->planeAnchorZ) / crossB[2];
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
    *obj = getAngle(*(f32*)(state + 0x34c), -*(f32*)(state + 0x344));
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
