/*
 * fireflylantern_steer - the target-steering/move helper the firefly-lantern
 * baddie family shares: steers the object toward its tracked target along the
 * path plane, clamped by a per-frame turn rate and a max step distance.
 * (callers: dll_00C9_enemy, duster.)
 */
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/dll/baddie_state.h"
#include "main/dll/objfsa.h"

extern void fn_8015536C(f32* out, f32* axis, f32 a, f32 b);
extern f32 lbl_803E2A00;
extern f32 lbl_803E2A04;
extern f32 lbl_803E2A08;

typedef struct FireflyState
{
    u8 pad00[0x358];
    f32 planeAnchorY; /* 0x358 */
    u8 pad35C[0x360 - 0x35C];
    f32 planeAnchorX; /* 0x360 */
    f32 planeAnchorZ; /* 0x364 */
} FireflyState;

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
    objMove((GameObject*)obj, moveDelta[0], moveDelta[1], moveDelta[2]);
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
