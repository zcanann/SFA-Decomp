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
#include "main/dll/duster_api.h"
#include "main/dll/fireflyLantern.h"

u32 fireflyLanternSteerTowardTarget(short* obj, int state, u32 turnTime, f32 maxDistance)
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
    GameObject* o = (GameObject*)obj;
    FireflyLanternState* fs = (FireflyLanternState*)state;

    vecA[0] = fs->wallPlane.anchorX;
    vecA[1] = fs->wallPlane.anchorY;
    vecA[2] = fs->wallPlane.anchorZ;
    PSVECSubtract(vecA, (f32*)(obj + 6), tmpA);
    d = PSVECDotProduct(tmpA, fs->wallPlane.normal);
    vecA[0] = fs->wallPlane.normal[0] * d + o->anim.localPosX;
    vecA[1] = fs->wallPlane.normal[1] * d + (objY = o->anim.localPosY);
    vecA[2] = fs->wallPlane.normal[2] * d + o->anim.localPosZ;
    axisA[0] = gWallPlaneZero;
    axisA[1] = gWallPlaneOne;
    axisA[2] = gWallPlaneZero;
    PSVECCrossProduct(axisA, fs->wallPlane.normal, crossA);
    PSVECNormalize(crossA, crossA);
    if (gWallPlaneZero != crossA[0])
    {
        dxA = (o->anim.localPosX - fs->wallPlane.anchorX) / crossA[0];
    }
    else
    {
        dxA = (o->anim.localPosZ - fs->wallPlane.anchorZ) / crossA[2];
    }
    targetObj = *(int*)&((BaddieState*)state)->trackedObj;
    targetPos[0] = ((GameObject*)targetObj)->anim.localPosX;
    targetPos[1] = gFireflyLanternTargetHeightOffset + ((GameObject*)targetObj)->anim.localPosY;
    targetPos[2] = ((GameObject*)targetObj)->anim.localPosZ;
    vecB[0] = fs->wallPlane.anchorX;
    vecB[1] = fs->wallPlane.anchorY;
    vecB[2] = fs->wallPlane.anchorZ;
    PSVECSubtract(vecB, targetPos, tmpB);
    d = PSVECDotProduct(tmpB, fs->wallPlane.normal);
    vecB[0] = fs->wallPlane.normal[0] * d + targetPos[0];
    vecB[1] = fs->wallPlane.normal[1] * d + (targetY = targetPos[1]);
    vecB[2] = fs->wallPlane.normal[2] * d + targetPos[2];
    axisB[0] = gWallPlaneZero;
    axisB[1] = gWallPlaneOne;
    axisB[2] = gWallPlaneZero;
    PSVECCrossProduct(axisB, fs->wallPlane.normal, crossB);
    PSVECNormalize(crossB, crossB);
    if (gWallPlaneZero != crossB[0])
    {
        d = (targetPos[0] - fs->wallPlane.anchorX) / crossB[0];
    }
    else
    {
        d = (targetPos[2] - fs->wallPlane.anchorZ) / crossB[2];
    }
    dxDiff = dxA - d;
    dy = objY - targetY;
    angle = getAngle(-dy, dxDiff) & 0xffff;
    rot = o->anim.rotY;
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
    if (turnStep > gWallPlaneOne)
    {
        turnStep = gWallPlaneOne;
    }
    angleStep = (int)((f32)delta * turnStep);
    *obj = (s16)(rot + angleStep);
    o->anim.rotZ = 0x4000;
    o->anim.rotY = *obj;
    *obj = getAngle(fs->wallPlane.normal[2], -fs->wallPlane.normal[0]);
    turnStep = sqrtf(dxDiff * dxDiff + dy * dy);
    if (turnStep > maxDistance)
    {
        f32 ratio = gWallPlaneOne / turnStep;
        dxDiff = maxDistance * (dxDiff * ratio);
        dy = maxDistance * (dy * ratio);
    }
    dxA -= dxDiff;
    turnStep = objY - dy;
    wallPlaneClampMoveTarget(moveTarget, &fs->wallPlane, dxA, turnStep);
    PSVECSubtract(moveTarget, (f32*)(obj + 6), moveDelta);
    objMove((GameObject*)obj, moveDelta[0], moveDelta[1], moveDelta[2]);
    turnStep = gWallPlaneZero;
    o->anim.velocityX = turnStep;
    o->anim.velocityY = turnStep;
    o->anim.velocityZ = turnStep;
    if (angleStep < 0)
    {
        angleStep = -angleStep;
    }
    return angleStep & 0xffff;
}
