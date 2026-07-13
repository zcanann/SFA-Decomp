/*
 * mmp_gyservent - the MMP (Moon Mountain Pass) geyser-vent object.
 *
 * Setup (objFn_80198fa4) reads the placement's class-specific bytes to
 * orient the vent (rotX from byte 0x3d, rotY from byte 0x3e), scales the
 * eruption reach from byte 0x3a, then builds a clip plane in the vent's
 * local frame: a forward direction is transformed out of the vent matrix
 * and stored with its plane normal and offset, and the inverse rotation
 * is transposed into the state's 4x4 at +0x38.
 * nearRadiusSq is the squared "near" radius and reach the eruption reach
 * used by the sequence functions.
 *
 * The two sequence callbacks classify the player's position against two
 * target points (the vent's two reach endpoints) and pass a discrete
 * "leg" code to objInterpretSeq, selecting which scripted reaction runs.
 * objSeqMoveFn_80199188 gates on height (dy) plus squared distance using a
 * speed byte from placement 0x3b; objSeqFn_801992ec gates on pure squared
 * distance against nearRadiusSq.
 */
#include "main/game_object.h"
#include "dolphin/os/OSReport.h"
#include "main/dll/mmp_gyservent.h"
#include "main/vecmath.h"

extern void objInterpretSeq(int obj, int seqArg, s8 legCode, int distSq);

/* placement instance id (+0x14) of the one vent that emits a debug OSReport */
#define MMP_GYSERVENT_DEBUG_INSTANCE_ID 0x46a31

/* placement (WmSpiritPlaceMapData) byte offsets read at setup / per-frame */
#define MMP_GYSERVENT_PLACE_REACH    0x3a /* eruption reach scale byte */
#define MMP_GYSERVENT_PLACE_SPEED    0x3b /* per-frame speed byte */
#define MMP_GYSERVENT_PLACE_ROTX     0x3d /* rotX (low 6 bits) */
#define MMP_GYSERVENT_PLACE_ROTY     0x3e /* rotY */
#define MMP_GYSERVENT_PLACE_INSTANCE 0x14 /* instance id */

extern char lbl_8032253C[]; /* OSReport format string (.data) */
extern f32
    lbl_803E40D8; /* 0.0f - used both as a plain 0.0f and, via *(f32*)&lbl_803E40D8, as the y arg of Matrix_TransformPoint (same value) */
extern f32 lbl_803E40DC; /* 0.0625f (1/16) - reach scale per height byte */
extern f32 lbl_803E40E0; /* 1.0f */
extern f32 lbl_803E40E4; /* 100.0f - reach multiplier */
extern f32 lbl_803E40E8; /* 145.0f - near-radius multiplier */

void objFn_80198fa4(GameObject* obj, MmpGyserventPlacement* placement)
{
    MmpGyserventState* state;
    MatrixTransform xf;
    union
    {
        f32 m[16];
        f64 a8;
    } rotU;
    f32 outY;
    f32 outZ;
    f32 outX;
    f32 posMtx[16];
#define rotMtx rotU.m

    state = obj->extra;
    obj->anim.rotX = (s16)((placement->rotX & 0x3f) << 10);
    obj->anim.rotY = (s16)(placement->rotY << 8);
    obj->anim.rootMotionScale =
        obj->anim.modelInstance->rootMotionScaleBase * ((float)(u32)placement->reachScale * lbl_803E40DC);

    xf.rotX = obj->anim.rotX;
    xf.rotY = obj->anim.rotY;
    xf.rotZ = obj->anim.rotZ;
    xf.scale = lbl_803E40E0;
    xf.x = lbl_803E40D8;
    xf.y = lbl_803E40D8;
    xf.z = lbl_803E40D8;
    setMatrixFromObjectPos(posMtx, &xf);
    Matrix_TransformPoint(posMtx, lbl_803E40D8, *(f32*)&lbl_803E40D8, lbl_803E40E0, &outY, &outZ, &outX);
    state->planeNormalX = outY;
    state->planeNormalY = outZ;
    state->planeNormalZ = outX;
    state->planeOffset =
        -(obj->anim.worldPosZ * outX + (obj->anim.worldPosX * outY + obj->anim.worldPosY * outZ));

    xf.rotX = (s16)-obj->anim.rotX;
    xf.rotY = (s16)-obj->anim.rotY;
    xf.rotZ = 0;
    xf.scale = lbl_803E40E0;
    xf.x = -obj->anim.worldPosX;
    xf.y = -obj->anim.worldPosY;
    xf.z = -obj->anim.worldPosZ;
    mtxRotateByVec3s(rotMtx, &xf);
    mtx44Transpose(rotMtx, (f32*)((char*)state + 0x38));

    state->reach = lbl_803E40E4 * obj->anim.rootMotionScale;
    state->nearRadiusSq = (lbl_803E40E8 * obj->anim.rootMotionScale) * (lbl_803E40E8 * obj->anim.rootMotionScale);
    if (placement->base.mapId == MMP_GYSERVENT_DEBUG_INSTANCE_ID)
    {
        OSReport(lbl_8032253C);
    }
#undef rotMtx
}

void objSeqMoveFn_80199188(GameObject* obj, int seqArg)
{
    f32 distSqA;
    f32 dyB;
    f32 dyA;
    f32 speed;
    f32 t;
    f32 distSqB;
    bool nearEnd;
    s8 leg;
    MmpGyserventState* state;

    state = (obj)->extra;
    speed = (float)(s32)(((MmpGyserventPlacement*)obj->anim.placementData)->speed * 2);
    t = state->reachAX - (obj)->anim.worldPosX;
    dyA = state->reachAY - (obj)->anim.worldPosY;
    distSqA = state->reachAZ - (obj)->anim.worldPosZ;
    distSqA = t * t + distSqA * distSqA;
    t = state->reachBX - (obj)->anim.worldPosX;
    dyB = state->reachBY - (obj)->anim.worldPosY;
    distSqB = state->reachBZ - (obj)->anim.worldPosZ;
    distSqB = t * t + distSqB * distSqB;
    t = state->nearRadiusSq;
    if (distSqB < t)
    {
        dyB = (dyB < 0.0f) ? -dyB : dyB;
        if (dyB < speed)
        {
            nearEnd = false;
            if (distSqA < t)
            {
                dyA = (dyA < 0.0f) ? -dyA : dyA;
                if (dyA < speed)
                {
                    nearEnd = true;
                }
            }
            leg = nearEnd ? 2 : 1;
            goto end;
        }
    }
    nearEnd = false;
    if (distSqA < t)
    {
        dyA = (dyA < 0.0f) ? -dyA : dyA;
        if (dyA < speed)
        {
            nearEnd = true;
        }
    }
    leg = nearEnd ? -1 : -2;
end:
    objInterpretSeq((int)obj, seqArg, leg, distSqB);
}

void objSeqFn_801992ec(GameObject* obj, int seqArg)
{
    MmpGyserventState* state;
    f32 dx0, dy0, dz0, d0;
    f32 dx1, dy1, dz1, d1;
    s8 cat;

    state = (MmpGyserventState*)(obj)->extra;

    dx0 = state->reachAX - (obj)->anim.worldPosX;
    dy0 = state->reachAY - (obj)->anim.worldPosY;
    dz0 = state->reachAZ - (obj)->anim.worldPosZ;
    d0 = dx0 * dx0 + dy0 * dy0 + dz0 * dz0;

    dx1 = state->reachBX - (obj)->anim.worldPosX;
    dy1 = state->reachBY - (obj)->anim.worldPosY;
    dz1 = state->reachBZ - (obj)->anim.worldPosZ;
    d1 = dx1 * dx1 + dy1 * dy1 + dz1 * dz1;

    if (d1 < state->nearRadiusSq)
    {
        cat = (d0 < state->nearRadiusSq) ? 2 : 1;
    }
    else
    {
        cat = (d0 < state->nearRadiusSq) ? -1 : -2;
    }
    objInterpretSeq((int)obj, seqArg, cat, d1);
}
