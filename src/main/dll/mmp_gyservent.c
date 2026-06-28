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
#include "main/dll/dll_80220608_shared.h"

/* placement instance id (+0x14) of the one vent that emits a debug OSReport */
#define MMP_GYSERVENT_DEBUG_INSTANCE_ID 0x46a31

/* placement (WmSpiritPlaceMapData) byte offsets read at setup / per-frame */
#define MMP_GYSERVENT_PLACE_REACH    0x3a /* eruption reach scale byte */
#define MMP_GYSERVENT_PLACE_SPEED    0x3b /* per-frame speed byte */
#define MMP_GYSERVENT_PLACE_ROTX     0x3d /* rotX (low 6 bits) */
#define MMP_GYSERVENT_PLACE_ROTY     0x3e /* rotY */
#define MMP_GYSERVENT_PLACE_INSTANCE 0x14 /* instance id */

typedef struct MmpGyserventState
{
    u8 pad0[0x4 - 0x0];
    f32 nearRadiusSq;  /* 0x04: squared near-distance threshold */
    u8 pad8[0xC - 0x8];
    f32 planeNormalX;  /* 0x0C: clip-plane normal (vent local forward) */
    f32 planeNormalY;  /* 0x10 */
    f32 planeNormalZ;  /* 0x14 */
    f32 planeOffset;   /* 0x18: plane d term */
    f32 reachAX;       /* 0x1C: reach endpoint A */
    f32 reachAY;       /* 0x20 */
    f32 reachAZ;       /* 0x24 */
    f32 reachBX;       /* 0x28: reach endpoint B */
    f32 reachBY;       /* 0x2C */
    f32 reachBZ;       /* 0x30 */
    f32 reach;         /* 0x34: eruption reach distance */
} MmpGyserventState;

STATIC_ASSERT(offsetof(MmpGyserventState, nearRadiusSq) == 0x04);
STATIC_ASSERT(offsetof(MmpGyserventState, planeNormalX) == 0x0C);
STATIC_ASSERT(offsetof(MmpGyserventState, planeOffset) == 0x18);
STATIC_ASSERT(offsetof(MmpGyserventState, reachAX) == 0x1C);
STATIC_ASSERT(offsetof(MmpGyserventState, reachBX) == 0x28);
STATIC_ASSERT(offsetof(MmpGyserventState, reach) == 0x34);

extern void mtxRotateByVec3s(f32* mtx, void* transform);
extern void mtx44Transpose(void* m, void* out);
extern void OSReport(const char* msg, ...);
extern void objInterpretSeq(void* obj, int arg2, s8 legCode, int distanceSquared);
extern char lbl_8032253C[]; /* OSReport format string (.data) */
extern f32 lbl_803E40D8;     /* 0.0f - used both as a plain 0.0f and, via *(f32*)&lbl_803E40D8, as the y arg of Matrix_TransformPoint (same value) */
extern f32 lbl_803E40DC;     /* 0.0625f (1/16) - reach scale per height byte */
extern f32 lbl_803E40E0;     /* 1.0f */
extern f32 lbl_803E40E4;     /* 100.0f - reach multiplier */
extern f32 lbl_803E40E8;     /* 145.0f - near-radius multiplier */

/* obj is the GameObject, but typed s16* so the rotX/rotY/rotZ word writes
 * (obj[0..2]) and the f32 scale at obj+4 land at the exact offsets; it is cast
 * to GameObject* where needed. */
void objFn_80198fa4(s16* obj, void* placement)
{
    MmpGyserventState* state;
    s16 rot[3];
    union
    {
        f32 m[18];
        f64 a8;
    } rotU;
    f32 outY;
    f32 outZ;
    f32 outX;
    f32 mtx[20];
#define rotMtx rotU.m

    state = (MmpGyserventState*)((GameObject*)obj)->extra;
    obj[0] = (s16)((*(u8*)((char*)placement + MMP_GYSERVENT_PLACE_ROTX) & 0x3f) << 10);
    obj[1] = (s16)(*(u8*)((char*)placement + MMP_GYSERVENT_PLACE_ROTY) << 8);
    *(f32*)(obj + 4) =
        ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase *
        (((float)(u32)(*(u8*)((char*)placement + MMP_GYSERVENT_PLACE_REACH))) * lbl_803E40DC);

    rot[0] = obj[0];
    rot[1] = obj[1];
    rot[2] = obj[2];
    mtx[0] = lbl_803E40E0;
    mtx[1] = lbl_803E40D8;
    mtx[2] = lbl_803E40D8;
    mtx[3] = lbl_803E40D8;
    setMatrixFromObjectPos(&mtx[4], rot);
    Matrix_TransformPoint((f32*)((char*)mtx + 16), lbl_803E40D8, *(f32*)&lbl_803E40D8, lbl_803E40E0, &outY, &outZ, &outX);
    state->planeNormalX = outY;
    state->planeNormalY = outZ;
    state->planeNormalZ = outX;
    state->planeOffset =
        -(((GameObject*)obj)->anim.worldPosZ * outX +
            (((GameObject*)obj)->anim.worldPosX * outY +
                ((GameObject*)obj)->anim.worldPosY * outZ));

    rot[0] = (s16)(-obj[0]);
    rot[1] = (s16)(-obj[1]);
    rot[2] = 0;
    mtx[0] = lbl_803E40E0;
    mtx[1] = -((GameObject*)obj)->anim.worldPosX;
    mtx[2] = -((GameObject*)obj)->anim.worldPosY;
    mtx[3] = -((GameObject*)obj)->anim.worldPosZ;
    mtxRotateByVec3s(rotMtx, rot);
    mtx44Transpose(rotMtx, (char*)state + 0x38);

    state->reach = lbl_803E40E4 * *(f32*)(obj + 4);
    state->nearRadiusSq =
        (lbl_803E40E8 * *(f32*)(obj + 4)) * (lbl_803E40E8 * *(f32*)(obj + 4));
    if (*(int*)((char*)placement + MMP_GYSERVENT_PLACE_INSTANCE) == MMP_GYSERVENT_DEBUG_INSTANCE_ID)
    {
        OSReport(lbl_8032253C);
    }
#undef rotMtx
}

void objSeqMoveFn_80199188(void* obj, int arg2)
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

    state = ((GameObject*)obj)->extra;
    speed = (float)(s32)(*(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + MMP_GYSERVENT_PLACE_SPEED) * 2);
    t = state->reachAX - ((GameObject*)obj)->anim.worldPosX;
    dyA = state->reachAY - ((GameObject*)obj)->anim.worldPosY;
    distSqA = state->reachAZ - ((GameObject*)obj)->anim.worldPosZ;
    distSqA = t * t + distSqA * distSqA;
    t = state->reachBX - ((GameObject*)obj)->anim.worldPosX;
    dyB = state->reachBY - ((GameObject*)obj)->anim.worldPosY;
    distSqB = state->reachBZ - ((GameObject*)obj)->anim.worldPosZ;
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
    objInterpretSeq(obj, arg2, leg, distSqB);
}

void objSeqFn_801992ec(void* obj, int arg2)
{
    MmpGyserventState* state;
    f32 dx0, dy0, dz0, d0;
    f32 dx1, dy1, dz1, d1;
    s8 cat;

    state = (MmpGyserventState*)((GameObject*)obj)->extra;

    dx0 = state->reachAX - ((GameObject*)obj)->anim.worldPosX;
    dy0 = state->reachAY - ((GameObject*)obj)->anim.worldPosY;
    dz0 = state->reachAZ - ((GameObject*)obj)->anim.worldPosZ;
    d0 = dx0 * dx0 + dy0 * dy0 + dz0 * dz0;

    dx1 = state->reachBX - ((GameObject*)obj)->anim.worldPosX;
    dy1 = state->reachBY - ((GameObject*)obj)->anim.worldPosY;
    dz1 = state->reachBZ - ((GameObject*)obj)->anim.worldPosZ;
    d1 = dx1 * dx1 + dy1 * dy1 + dz1 * dz1;

    if (d1 < state->nearRadiusSq)
    {
        cat = (d0 < state->nearRadiusSq) ? 2 : 1;
    }
    else
    {
        cat = (d0 < state->nearRadiusSq) ? -1 : -2;
    }
    objInterpretSeq(obj, arg2, cat, d1);
}
