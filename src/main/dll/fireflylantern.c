/*
 * fireflylantern - named for the firefly-lantern DLL object whose source
 * this TU was split from; it owns the generic rom-curve path-walk and
 * target-steering helpers that object first defined, which the PinPon
 * baddie then reuses (retail OBJECTS.bin name "PinPon" for dispatch defNo
 * 0x251; it uses the "fox fightbreath" SFX). These four routines live in
 * this object but are linked into sibling baddie DLLs:
 *   - pinPon_updateEngaged  per-frame update: walks the rom curve path, faces the
 *     player, drives the move/look helpers and plays attack-breath SFX.
 *   - pinPon_init  state init: seeds BaddieState path/speed fields and a
 *     random path phase/step.
 *   - fireflyLanternGetTargetAngleAndDistance computes the signed angle + planar distance from the
 *     object to its tracked target relative to the path plane.
 *   - fireflyLanternSteerTowardTarget  steers/moves the object toward its target along the
 *     path plane, clamped by a per-frame turn rate and max step.
 * (callers: dll_00C9_enemy, duster.)
 */
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/trig.h"
#include "main/vecmath.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/fall_ladders.h"
#include "main/dll/fireflyLantern.h"

#define FIREFLYLANTERN_HIT_VOLUME_SLOT 0xe

extern f32 gFireflyLanternPathStepScale;

typedef struct FireflyState
{
    u8 pad00[0x358];
    f32 planeAnchorY;
    u8 pad35C[0x360 - 0x35C];
    f32 planeAnchorX;
    f32 planeAnchorZ;
} FireflyState;

void pinPon_updateEngaged(GameObject* obj, int* state)
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
        ((Curve_AdvanceAlongPath(&curve->curve, 0.0f) != 0 || curve->atSegmentEnd != 0) &&
         ((*gRomCurveInterface)->goNextPoint(curve) != 0)) &&
        ((*gRomCurveInterface)->initCurve((RomCurveWalker*)*state, (void*)obj, 700.0f, (int*)&lbl_803DBCD0, -1) !=
         0))
    {
        *(u32*)&state[0xb7] &= ~0x2000LL;
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FIREFLYLANTERN_HIT_VOLUME_SLOT, 1, 0);
    flag = playerGetFlags3F0Bit5((GameObject*)(Obj_GetPlayerObject()));
    dvec[0] = ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX - (obj)->anim.localPosX;
    dvec[1] = 0.0f;
    dvec[2] = ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ - (obj)->anim.localPosZ;
    if (((u32)state[0xd0] != 0) && ((u32)state[0xd0] == (u32)Obj_GetPlayerObject()))
    {
        *(u32*)&state[0xb9] |= 0x10000LL;
        ((FireflyLanternState*)state)->trackTimer = 0.0f;
    }
    (obj)->anim.rotY = -(1024.0f * fn_80293DA4(0.19634955f * (f32)(u32)((BaddieState*)state)->userData1) -
                         (f32)(obj)->anim.rotY);
    if (flag == 0)
    {
        fval = 0.0f;
        (obj)->anim.velocityX = fval;
        (obj)->anim.velocityZ = fval;
        baddieTurnTowardPoint(obj, (int)state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                              ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 10, 0);
    }
    else
    {
        fn_8014C678(obj, state, dvec, 2.0f, 0.1f, 0.1f, 1);
        fn_8014CD1C(obj, state, 0xf, 7.5f, 1.0f, 0);
    }
    if (state[0xb7] & 0x40000000U)
    {
        fval = 0.0f;
        if (fval == ((FireflyLanternState*)state)->breathTimer)
        {
            if (flag == 0)
            {
                if ((obj)->anim.currentMoveProgress > 0.5f)
                {
                    ((FireflyLanternState*)state)->breathTimer = 300.0f;
                    ((BaddieState*)state)->userData2 += 1;
                }
                else
                {
                    ((FireflyLanternState*)state)->breathTimer = 120.0f;
                }
            }
            else if ((obj)->anim.currentMoveProgress > 0.5)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_kooshy_hit);
                ((BaddieState*)state)->unk308 = -0.02f;
            }
            else
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_kooshy_death);
                ((BaddieState*)state)->unk308 = 0.02f;
            }
        }
        else
        {
            ((FireflyLanternState*)state)->breathTimer = ((FireflyLanternState*)state)->breathTimer - timeDelta;
            if (((FireflyLanternState*)state)->breathTimer <= fval)
            {
                ((FireflyLanternState*)state)->breathTimer = fval;
                if ((obj)->anim.currentMoveProgress > 0.5)
                {
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_kooshy_hit);
                    ((BaddieState*)state)->unk308 = -0.02f;
                }
                else
                {
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_kooshy_death);
                    ((BaddieState*)state)->unk308 = 0.1f;
                }
            }
        }
    }
    ((BaddieState*)state)->userData1 += 1;
    (obj)->anim.rotY = (1024.0f * fn_80293DA4(0.19634955f * (f32)(u32)((BaddieState*)state)->userData1) +
                        (f32)(obj)->anim.rotY);
    baddieSpawnWaterRipple(obj, (BaddieState*)state);
}

void pinPon_init(GameObject* obj, void* state)
{
    float fval;
    u32 randVal;

    ((BaddieState*)state)->speedScale = 40.0f;
    ((BaddieState*)state)->unk2E4 = 0x8000009;
    ((BaddieState*)state)->unk308 = -0.02f;
    ((BaddieState*)state)->animDeltaScale = 0.1f;
    ((BaddieState*)state)->unk304 = 0.97f;
    ((BaddieState*)state)->unk320 = 0;
    fval = 1.5f;
    *(float*)&((BaddieState*)state)->eventFlags = 1.5f;
    ((BaddieState*)state)->unk321 = 1;
    ((BaddieState*)state)->unk318 = 1.0f;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fval;
    fval = 0.0f;
    ((FireflyLanternState*)state)->trackTimer = fval;
    ((FireflyLanternState*)state)->breathTimer = fval;
    ((FireflyLanternState*)state)->anchorY = obj->anim.localPosY;
    randVal = randomGetRange(0, 0xff);
    ((BaddieState*)state)->userData1 = randVal;
    ((BaddieState*)state)->userData2 = 0;
    ((FireflyLanternState*)state)->unk330 = 30.0f;
    randVal = randomGetRange(0x32, 0x4b);
    fval = (f32)(s32)randVal;
    fval = gFireflyLanternPathStepScale * fval;
    ((BaddieState*)state)->pathStep = fval;
}

void fireflyLanternGetTargetAngleAndDistance(int obj, int state, u16* outAngle, float* outDistance)
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
    axisA[0] = gWallPlaneZero;
    axisA[1] = gWallPlaneOne;
    axisA[2] = gWallPlaneZero;
    PSVECCrossProduct(axisA, (f32*)(state + 0x344), crossA);
    PSVECNormalize(crossA, crossA);
    if (gWallPlaneZero != crossA[0])
    {
        dxDiff = (((GameObject*)obj)->anim.localPosX - ((FireflyState*)state)->planeAnchorX) / crossA[0];
    }
    else
    {
        dxDiff = (((GameObject*)obj)->anim.localPosZ - ((FireflyState*)state)->planeAnchorZ) / crossA[2];
    }
    targetObj = *(int*)&((BaddieState*)state)->trackedObj;
    targetPos[0] = ((GameObject*)targetObj)->anim.localPosX;
    targetPos[1] = gFireflyLanternTargetHeightOffset + ((GameObject*)targetObj)->anim.localPosY;
    targetPos[2] = ((GameObject*)targetObj)->anim.localPosZ;
    vecB[0] = ((FireflyState*)state)->planeAnchorX;
    vecB[1] = ((FireflyState*)state)->planeAnchorY;
    vecB[2] = ((FireflyState*)state)->planeAnchorZ;
    PSVECSubtract(vecB, targetPos, tmpB);
    d = PSVECDotProduct(tmpB, (f32*)(state + 0x344));
    vecB[0] = *(f32*)(state + 0x344) * d + targetPos[0];
    vecB[1] = *(f32*)(state + 0x348) * d + (dy = targetPos[1]);
    vecB[2] = *(f32*)(state + 0x34c) * d + targetPos[2];
    axisB[0] = gWallPlaneZero;
    axisB[1] = gWallPlaneOne;
    axisB[2] = gWallPlaneZero;
    PSVECCrossProduct(axisB, (f32*)(state + 0x344), crossB);
    PSVECNormalize(crossB, crossB);
    if (gWallPlaneZero != crossB[0])
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
