/* DLL 0x80198A00 - WaveAnimator model-matrix hook [80198A00-...) */

#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/dll/fx_800944A0_shared.h"
extern u32 objInterpretSeq(void* obj, int seqArg, s8 legCode, int distSq);
extern f32 lbl_803E40C8;
extern f32 lbl_803E40CC;
extern f32 lbl_803E40D8;


extern void PSMTXMultVec(f32 * mtx, f32 * in, f32 * out);
extern void OSReport(const char* msg, ...);
extern const char sMoonrockTriggerIdentFormat[];

#define MOONROCK_ANGLE_TO_RADIANS(angle) ((lbl_803E40C8 * (f32)(s32)(-(angle))) / lbl_803E40CC)

/* Per-object trigger-plane state stashed at obj->extra. Distinct from
 * MmpMoonrockState (which overlays the same slot for the carried-rock class):
 * here the block holds a clip plane (normal + D), the two segment endpoints the
 * RomCurve query was run against, a clip half-extent, and the 3x4 transform that
 * maps a hit point into trigger-local space. */
typedef struct MmpTriggerPlaneState {
    u8 header[0xC];      /* 0x00 */
    f32 normalX;         /* 0x0C plane normal */
    f32 normalY;         /* 0x10 */
    f32 normalZ;         /* 0x14 */
    f32 planeD;          /* 0x18 plane constant */
    f32 ptA[3];          /* 0x1C near segment endpoint */
    f32 ptB[3];          /* 0x28 far segment endpoint */
    f32 clipHalfExtent;  /* 0x34 trigger-local half size */
    f32 mtx[3][4];       /* 0x38 world->trigger-local transform */
} MmpTriggerPlaneState;

STATIC_ASSERT(offsetof(MmpTriggerPlaneState, normalX) == 0x0C);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, planeD) == 0x18);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, ptA) == 0x1C);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, ptB) == 0x28);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, clipHalfExtent) == 0x34);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, mtx) == 0x38);

/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */

/* WaterFallSpray_init: stash 3 signed-byte<<8 fields at obj+0..+4, clear
 * obj+0xf4, install WaterFallSpray_SeqFn as the think routine at obj+0xbc, then
 * pick one of two SFX-id pairs based on the range of obj->_4c->_14. */

/* sfxplayerObj_init: prime obj->_b0 with SFXPLAYER_OBJECT_FLAGS, then dispatch
 * on data->_1d: gamebit mode stores GameBit_Get(data->_18) at sub[0] if the
 * event id is positive; random-delay mode computes randomGetRange(data->_1e, data->_1f)
 * scaled by lbl_803E40BC as f32; cases 1 and >=3 are no-ops. */

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */

void fn_80198A00(u8* obj, int seqArg)
{
    MmpTriggerPlaneState* state;
    f32 hitDistance;
    int queryType;
    int curveHit;
    int frontBlocked;
    int rearBlocked;

    queryType = 0x17;
    state = (MmpTriggerPlaneState*)((GameObject*)obj)->extra;
    curveHit = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
        state->ptB[0], state->ptB[1], state->ptB[2], &queryType, 1,
        *(s16*)(*(u8**)&((GameObject*)obj)->anim.placementData + 0x38));
    frontBlocked = ((int (*)(int, f32, f32, f32, f32*))(*gRomCurveInterface)->slot4C)(
        curveHit, state->ptB[0], state->ptB[1], state->ptB[2],
        &hitDistance);
    rearBlocked = ((int (*)(int, f32, f32, f32, f32*))(*gRomCurveInterface)->slot4C)(
        curveHit, state->ptA[0], state->ptA[1], state->ptA[2],
        &hitDistance);

    if (frontBlocked != 0)
    {
        if (rearBlocked == 0)
        {
            objInterpretSeq(obj, seqArg, 1, (int)hitDistance);
        }
        else
        {
            objInterpretSeq(obj, seqArg, 2, (int)hitDistance);
        }
    }
    else if (rearBlocked != 0)
    {
        objInterpretSeq(obj, seqArg, -1, (int)hitDistance);
    }
    else
    {
        objInterpretSeq(obj, seqArg, -2, (int)hitDistance);
    }
}

int fn_80198B68(u8* obj, f32* point)
{
    u8* data;
    f32 pointX;
    f32 pointY;
    f32 pointZ;
    f32 yawCos;
    f32 yawSin;
    f32 pitchCos;
    f32 pitchSin;
    f32 relZ;
    f32 relY;
    f32 relX;
    f32 localX;
    f32 localY;
    f32 localZ;
    f32 forward;

    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    pointX = point[0];
    pointY = point[1];
    pointZ = point[2];

    yawCos = mathSinf(MOONROCK_ANGLE_TO_RADIANS(((GameObject *)obj)->anim.rotX));
    yawSin = mathCosf(MOONROCK_ANGLE_TO_RADIANS(((GameObject *)obj)->anim.rotX));
    pitchCos = mathSinf(MOONROCK_ANGLE_TO_RADIANS(((GameObject *)obj)->anim.rotY));
    pitchSin = mathCosf(MOONROCK_ANGLE_TO_RADIANS(((GameObject *)obj)->anim.rotY));

    relX = pointX - ((GameObject*)obj)->anim.worldPosX;
    relY = pointY - ((GameObject*)obj)->anim.worldPosY;
    relZ = pointZ - ((GameObject*)obj)->anim.worldPosZ;
    localX = relX * yawSin - relZ * yawCos;
    forward = relX * yawCos + relZ * yawSin;
    localY = relY * pitchSin - forward * pitchCos;
    localZ = relY * pitchCos + forward * pitchSin;

    if (localX < 0.0f)
    {
        localX = -localX;
    }
    if (localY < 0.0f)
    {
        localY = -localY;
    }
    if (localZ < 0.0f)
    {
        localZ = -localZ;
    }

    if ((localX <= (f32)(s32)(data[0x3a] << 1)) &&
        (localY <= (f32)(s32)(data[0x3b] << 1)) &&
        (localZ <= (f32)(s32)(data[0x3c] << 1)))
    {
        return 1;
    }
    return 0;
}

void fn_80198DE8(u8* obj, int seqArg)
{
    MmpTriggerPlaneState* state;
    s8 triggerState;
    u8* data;
    f32 planeBase;
    f32 normalY;
    f32 normalX;
    f32 normalZ;
    f32 nearX;
    f32 nearY;
    f32 nearZ;
    f32 farX;
    f32 farY;
    f32 farZ;
    f32 prodY;
    f32 prodZ;
    f32 nearDist;
    f32 farDist;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 t;
    f32 localPos[3];

    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = (MmpTriggerPlaneState*)((GameObject*)obj)->extra;

    planeBase = state->planeD;
    normalZ = state->normalZ;
    nearZ = state->ptA[2];
    prodZ = normalZ * nearZ;
    normalX = state->normalX;
    nearX = state->ptA[0];
    normalY = state->normalY;
    nearY = state->ptA[1];
    prodY = normalY * nearY;
    nearDist = planeBase + (prodZ + (normalX * nearX + prodY));
    farZ = state->ptB[2];
    farX = state->ptB[0];
    farY = state->ptB[1];
    farDist = planeBase + (normalZ * farZ + (normalX * farX + normalY * farY));

    if (farDist < lbl_803E40D8)
    {
        triggerState = (nearDist < lbl_803E40D8) ? 2 : 1;
    }
    else
    {
        triggerState = (nearDist < lbl_803E40D8) ? -1 : -2;
    }

    if ((triggerState == 1) || (triggerState == -1))
    {
        deltaX = farX - nearX;
        deltaY = farY - nearY;
        deltaZ = farZ - nearZ;
        t = (((-normalX * nearX - prodY) - prodZ) - planeBase) /
            ((normalY * deltaY) + (normalX * deltaX) + (normalZ * deltaZ));

        localPos[0] = t * deltaX + nearX;
        localPos[1] = t * deltaY + state->ptA[1];
        localPos[2] = t * deltaZ + state->ptA[2];
        PSMTXMultVec(&state->mtx[0][0], localPos, localPos);

        if ((localPos[0] >= -state->clipHalfExtent) && (localPos[0] <= state->clipHalfExtent) &&
            (localPos[1] >= -state->clipHalfExtent) && (localPos[1] <= state->clipHalfExtent))
        {
            OSReport(sMoonrockTriggerIdentFormat, triggerState, *(u32*)(data + 0x14));
            objInterpretSeq(obj, seqArg, triggerState, (int)farDist);
        }
    }
}
