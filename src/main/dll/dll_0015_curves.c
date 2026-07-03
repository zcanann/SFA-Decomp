/*
 * DLL 0x0015 "curves" - terrain/ROM-curve collision driver and the
 * save-file settings shim for the main game.
 *
 * Two responsibilities live in this object:
 *  1. Per-frame collision against the level's ROM curve set
 *     (CurvesCollisionState). dll_15_func08 is the dispatcher: by
 *     state->subtype (OBJECT / POINT / NONE) it transforms an object's
 *     local sample points and segments into world space, traces them
 *     against the curves via the hitDetect helpers, and writes back
 *     world position, surface normal, tilt (pitch/roll) and water/floor/
 *     ceiling results. updateMode selects the segment resolver
 *     (random-point averaging, single trace, snap-to-hit, or the default
 *     averaging path). curves_getCurves caches the last queried object's
 *     hit list. The clamp at +/-0x3400 limits object rot Y/Z.
 *  2. Save-file/options access: loadSaveSettings pushes the persisted
 *     widescreen/subtitle/rumble/sound-mode/volume/HUD/camera settings to
 *     their subsystems, and the saveFileStruct_* helpers register, enable
 *     and query the debug/cheat option bitmask in SaveData.
 *
 * CurvesCollisionState->flags is a bitset of CURVES_COLLISION_STATE_*
 * features; pointCounts packs the local-point count (low nibble) and the
 * segment count (high nibble, CURVES_POINT_COUNT_SEGMENT_SHIFT).
 */
#include "dolphin/os.h"
#include "main/dll/savedata_struct.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/game_ui_interface.h"
#include "main/objlib.h"
#include <string.h>
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern int objBboxFn_800640cc(void* hitOut, void* pos, f32 radius, int mode, void* bbox, int obj,
                              s8 p7, int p8, int p9, int p10);
extern void fn_80063368(short* obj);
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern int hitDetectFn_80067958(int obj, void* startPoints, void* endPoints, int pointCount,
                                void* hitResults, int arg6);
extern void hitDetectFn_800691c0(void* a, void* b, int mask, int e);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern f32 PSVECMag(f32 * v);
extern f32 sqrtf(f32 x);
extern void setWidescreen(u8 enabled);
extern void setSubtitlesEnabled(u8 enabled);
extern void setRumbleEnabled(u8 enabled);
extern void audioSetSoundMode(int mode, u8 forceFlag);
extern void audioSetVolumes(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag);
extern u8 framesThisStep;
extern SaveData saveData;
extern u8 gSaveGameData[];
extern u32 sCurvesCachedHitCount;
extern u32 sCurvesCachedHitObj;
extern f32 lbl_803E0668;
extern const f32 lbl_803E066C;
extern const f32 lbl_803E068C;
extern const f32 gCurvesSurfaceNormalZThreshold;
extern const f32 lbl_803E067C;
extern const f32 lbl_803E0680;
extern const f32 lbl_803E0684;
extern const f32 lbl_803E0688;
extern const f32 lbl_803E0690;
extern const f32 lbl_803E06A0;
extern const f32 gCurvesBoundsMaxSeed;
extern const f32 gCurvesBoundsMinSeed;
extern const f32 lbl_803E06AC;
extern const f32 lbl_803E06B0;
extern const f32 lbl_803E06B4;
extern const f32 lbl_803E06B8;
extern const f32 lbl_803E06BC;
extern const f32 lbl_803E06C0;

typedef struct CurvesHitScratch
{
    u8 unk0[0x40];
    f32 scale;
    u8 unk44[0x10];
    u8 type;
    u8 unk55[0x13];
} CurvesHitScratch;

typedef struct CurvesTransformScratch
{
    s16 angles[3];
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CurvesTransformScratch;

static inline u32 RomCurve_GetId(RomCurveDef* curve)
{
    return curve->id;
}

static inline int RomCurve_IsLinkIdValid(int linkId)
{
    return -1 < linkId;
}

static inline RomCurveDef* RomCurve_FindByIdInline(u32 curveId)
{
    RomCurveDef* curve;
    int high;
    int low;
    int mid;

    if ((s32)curveId < 0)
    {
        return NULL;
    }

    high = nRomCurves - 1;
    low = 0;
    while (high >= low)
    {
        mid = (high + low) >> 1;
        curve = romCurves[mid];
        if (curveId > curve->id)
        {
            low = mid + 1;
        }
        else if (curveId < curve->id)
        {
            high = mid - 1;
        }
        else
        {
            return curve;
        }
    }

    return NULL;
}

static inline int RomCurve_noUnblockedLinks(RomCurvePlacementDef* curve)
{
    int bit;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++)
    {
        if ((s32)curve->base.linkIds[bit] != -1 && (curve->base.blockedLinkMask & (1 << bit)) == 0)
        {
            return 0;
        }
    }
    return 1;
}

static inline int RomCurve_noBlockedLinks(RomCurvePlacementDef* curve)
{
    int bit;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++)
    {
        if ((s32)curve->base.linkIds[bit] != -1 && (curve->base.blockedLinkMask & (1 << bit)) != 0)
        {
            return 0;
        }
    }
    return 1;
}

/*
 * Retail source-tag string: Hcurves.c: MAX_ROMCURVES exceeded!!
 */

#pragma opt_loop_invariants off
void curves_countRandomPoints(int obj, CurvesCollisionState* collision)
{
    GameObject* object;
    RomCurvePoint** list;
    int found1;
    int hits;
    RomCurvePoint* point;
    f32 pointY;
    f32 dx;
    f32 dz;
    int ang;
    int i;
    int count;
    int j;
    f32 sum0;
    f32 sum1;
    f32 sum2;
    f32 sum3;
    RomCurvePoint** hitOut;
    f32 heights[5];
    extern int getAngle(f32 deltaX, f32 deltaZ);

    object = (GameObject*)obj;
    if ((int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT == 4)
    {
        sum0 = *(const f32*)&lbl_803E0668;
        count = 0;
        sum3 = sum2 = sum1 = sum0;
        for (i = 0; i < (int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT; i++)
        {
            heights[i] = collision->points[i][1];
            hits = hitDetectFn_80065e50(obj, collision->points[i][0], object->anim.worldPosY,
                                        collision->points[i][2], &hitOut, -1, 0);
            found1 = 0;
            if (hits != 0)
            {
                list = hitOut;
                for (j = 0; j < hits; j++)
                {
                    if (!found1)
                    {
                        point = *list;
                        pointY = point->x;
                        if ((pointY < lbl_803E066C + object->anim.worldPosY) &&
                            ((s8)point->type != ROMCURVE_POINT_TYPE_WATER))
                        {
                            heights[i] = point->x;
                            sum1 = sum1 + point->y;
                            sum2 = sum2 + point->z;
                            sum3 = sum3 + point->w;
                            sum0 = sum0 + pointY;
                            count++;
                            found1 = 1;
                        }
                    }
                    list = list + 1;
                }
            }
            collision->points[i][1] = heights[i];
        }
        if (count != 0)
        {
            object->anim.worldPosY = sum0 / (f32)(s32)count;
            collision->surfaceNormalX = sum1 / (f32)(s32)count;
            collision->surfaceNormalY = sum2 / (f32)(s32)count;
            collision->surfaceNormalZ = sum3 / (f32)(s32)count;
            collision->surfaceCounter = 1;
        }
        else
        {
            collision->surfaceCounter = 0;
        }
        dx = heights[3];
        dz = collision->segmentLocalPoints[11];
        dz = dz - collision->segmentLocalPoints[2];
        dx = dx - heights[0];
        getAngle(dx, dz);
        ang = getAngle(dx, dz);
        object->anim.rotY = -ang;
        if (((int)collision->flags & 0x400) != 0)
        {
            dx = heights[1];
            dz = collision->segmentLocalPoints[3] - collision->segmentLocalPoints[0];
            dx = dx - heights[0];
            object->anim.rotZ = getAngle(dx, dz);
        }
    }
}

#pragma opt_loop_invariants reset
void fn_800E56A4(int obj, CurvesCollisionState* collision)
{
    RomCurvePoint* point;
    RomCurvePoint* points;
    int hitCount;
    int count;
    int pointIndex;
    f32 delta[3];
    CurvesHitScratch hitScratch;
    f32 startX;
    f32 startZ;

    startX = collision->points[1][0];
    startZ = collision->points[1][2];
    if ((s32)(collision->flags & 0x100000) == 0)
    {
        ((GameObject*)obj)->anim.worldPosX = startX;
        ((GameObject*)obj)->anim.worldPosZ = startZ;
        ((GameObject*)obj)->anim.worldPosY = collision->points[0][1];
    }

    points = curves_getCurves(obj, collision->points[1][0], collision->points[1][2], (u32*)&hitCount, 0);
    for (pointIndex = 0, point = points, count = hitCount; pointIndex < count;)
    {
        if (((s8)point->type != ROMCURVE_POINT_TYPE_WATER) && (point->z > gCurvesSurfaceNormalZThreshold) &&
            (point->x <= collision->points[1][1]) && (point->x > collision->points[0][1]))
        {
            collision->traceStart[0][0] = collision->points[1][0];
            collision->traceStart[0][1] = collision->points[1][1];
            collision->traceStart[0][2] = collision->points[1][2];
            collision->points[0][0] = collision->points[1][0];
            collision->points[0][1] = points[pointIndex].x;
            collision->points[0][2] = collision->points[1][2];
            hitDetectFn_80067958(obj, collision->traceStart[0], collision->points[0], 1, collision->segmentHitPlanes,
                                 0);
            break;
        }
        point++;
        pointIndex++;
    }

    if (((GameObject*)obj)->anim.classId == 1)
    {
        collision->traceStart[2][0] = collision->points[1][0];
        collision->traceStart[2][1] = collision->points[1][1];
        collision->traceStart[2][2] = collision->points[1][2];
        collision->points[2][0] = collision->points[1][0];
        collision->points[2][1] = lbl_803E067C + collision->points[1][1];
        collision->points[2][2] = collision->points[1][2];
        hitScratch.scale = lbl_803E0680;
        hitScratch.type = 3;
        hitDetectFn_80067958(obj, collision->traceStart[2], collision->points[2], 1, &hitScratch, 0);
    }

    PSVECSubtract(collision->points[0], collision->points[1], delta);
    if (((s32)(collision->flags & 0x8000000) != 0) || (PSVECMag(delta) > lbl_803E0684))
    {
        collision->traceStart[0][0] = collision->points[1][0];
        collision->traceStart[0][1] = collision->points[1][1];
        collision->traceStart[0][2] = collision->points[1][2];
        collision->points[0][0] = collision->points[1][0];
        collision->points[0][1] = collision->points[1][1] - lbl_803E0688;
        collision->points[0][2] = collision->points[1][2];
        hitDetectFn_80067958(obj, collision->traceStart[0], collision->points[0], 1, collision->segmentHitPlanes, 0);
    }

    collision->surfaceNormalX = collision->segmentHitPlanes[0][0];
    collision->surfaceNormalY = collision->segmentHitPlanes[0][1];
    collision->surfaceNormalZ = collision->segmentHitPlanes[0][2];
    collision->contactObj = collision->traceHitObj;
    if (collision->contactObj != 0)
    {
        ObjHits_AddContactObject(collision->contactObj, obj);
    }
}

#pragma opt_common_subs off
void fn_800E58FC(int obj, CurvesCollisionState* collision)
{
    f32 sumY;
    CurvesTransformScratch transform;
    f32 localX[4];
    f32 localY[4];
    f32 localZ[4];
    f32 matrix[16];
    f32 averageScale;
    f32 scale;
    f32 secondArg;
    f32 zero;
    s8 idx1;
    s8 idx2;
    s8 idx3;
    u8 pointCount;
    f32* pointX;
    f32* pointYZ;
    s32 pointLimit;
    f32* point;
    f32* outX;
    f32* outZ;
    f32* outY;
    s16 pointIndex;
    s16 i;
    int angle;
    extern int getAngle(f32 deltaX, f32 deltaZ);

    collision->surfaceNormalX = collision->segmentHitPlanes[0][0];
    collision->surfaceNormalY = collision->segmentHitPlanes[0][1];
    collision->surfaceNormalZ = collision->segmentHitPlanes[0][2];
    pointCount = collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT;
    if ((pointCount == 2) || (pointCount == 4))
    {
        zero = lbl_803E0668;
        ((GameObject*)obj)->anim.worldPosX = zero;
        ((GameObject*)obj)->anim.worldPosY = zero;
        ((GameObject*)obj)->anim.worldPosZ = zero;

        pointIndex = 0;
        pointX = (f32*)collision;
        pointYZ = (f32*)collision;
        pointLimit = pointCount * 3;
        for (; pointIndex < pointLimit; pointIndex += 3)
        {
            ((GameObject*)obj)->anim.worldPosX += pointX[2];
            ((GameObject*)obj)->anim.worldPosY += pointYZ[3];
            ((GameObject*)obj)->anim.worldPosZ += pointYZ[4];
            pointX += 3;
            pointYZ += 3;
        }

        scale = lbl_803E068C;
        averageScale = scale / pointCount;
        ((GameObject*)obj)->anim.worldPosX *= averageScale;
        ((GameObject*)obj)->anim.worldPosY *= averageScale;
        ((GameObject*)obj)->anim.worldPosZ *= averageScale;

        if ((s32)(collision->flags & 0x8600) != 0)
        {
            transform.angles[0] = -((GameObject*)obj)->anim.rotX;
            transform.angles[1] = -((GameObject*)obj)->anim.rotY;
            transform.angles[2] = -((GameObject*)obj)->anim.rotZ;
            transform.scale = scale;
            transform.x = -((GameObject*)obj)->anim.worldPosX;
            transform.y = -((GameObject*)obj)->anim.worldPosY;
            transform.z = -((GameObject*)obj)->anim.worldPosZ;
            mtxRotateByVec3s(matrix, transform.angles);

            i = 0;
            outZ = localZ;
            outY = localY;
            outX = localX;
            point = (f32*)collision;
            for (; i < pointCount; i++)
            {
                Matrix_TransformPoint(matrix, point[2], point[3], point[4], outX, outY, outZ);
                point += 3;
                outZ++;
                outY++;
                outX++;
            }

            idx1 = 1;
            idx2 = 2;
            idx3 = 3;
            if (pointCount == 2)
            {
                idx1 = 0;
                idx2 = 1;
                idx3 = 1;
            }
            if ((s32)(collision->flags & 0x8000) != 0)
            {
                angle = (u16)getAngle((localX[0] + localX[idx1]) - (localX[idx2] + localX[idx3]),
                                 (localZ[0] + localZ[idx1]) - (localZ[idx2] + localZ[idx3]));
                ((GameObject*)obj)->anim.rotX += (s16)(u16)(angle + 0x8000) >> 2;
            }
            if ((s32)(collision->flags & 0x200) != 0)
            {
                f32 sumZ;
                f32 k;
                sumZ = localZ[idx2] - localZ[idx1];
                sumZ += localZ[idx3] - localZ[0];
                secondArg = sumZ * (k = lbl_803E0690);
                sumY = localY[idx2] - localY[idx1];
                sumY += localY[idx3] - localY[0];
                sumY *= k;
                angle = getAngle(sumY, secondArg);
                collision->tiltPitch = -angle;
            }
            if ((pointCount == 4) && ((s32)(collision->flags & 0x400) != 0))
            {
                f32 sumX;
                f32 k;
                sumX = localX[idx1] - localX[0];
                sumX += localX[idx2] - localX[idx3];
                secondArg = sumX * (k = lbl_803E0690);
                sumY = localY[idx1] - localY[0];
                sumY += localY[idx2] - localY[idx3];
                sumY *= k;
                angle = getAngle(sumY, secondArg);
                collision->tiltRoll = angle;
            }
        }
    }
    else
    {
        ((GameObject*)obj)->anim.worldPosX = collision->points[0][0];
        ((GameObject*)obj)->anim.worldPosY = collision->points[0][1];
        ((GameObject*)obj)->anim.worldPosZ = collision->points[0][2];
    }
}
#pragma opt_common_subs reset

#pragma dont_inline on
#pragma opt_common_subs off
void fn_800E5CBC(short* obj, int state)
{
    CurvesCollisionState* collision;
    f32 normalZ;
    short pitch;
    short angle;
    f32 dy;
    f32 dx;
    f32 dz;
    short outVec[4];
    f32 matrixBuf[20];

    collision = (CurvesCollisionState*)state;
    if (((s8)collision->surfaceFlags & 0x10) != 0)
    {
        outVec[0] = -*obj;
        if (*(short**)(obj + 0x18) != NULL)
        {
            outVec[0] = outVec[0] - **(short**)(obj + 0x18);
        }
        outVec[1] = 0;
        outVec[2] = 0;
        matrixBuf[0] = lbl_803E068C;
        matrixBuf[1] = lbl_803E0668;
        matrixBuf[2] = lbl_803E0668;
        matrixBuf[3] = lbl_803E0668;
        mtxRotateByVec3s(&matrixBuf[4], outVec);
        Matrix_TransformPoint(&matrixBuf[4], (double)collision->surfaceNormalX,
                              (double)collision->surfaceNormalY, (double)collision->surfaceNormalZ,
                              &dy, &dx, &dz);
        angle = getAngle(dx, dz);
        pitch = 0x4000 - angle;
        collision->tiltPitchTarget = pitch;
        collision->tiltPitch =
            collision->tiltPitch +
            ((int)((u32)framesThisStep * ((int)pitch - collision->tiltPitch)) >> 3);
        angle = getAngle(dx, dy);
        pitch = -(0x4000 - angle);
        collision->tiltRollTarget = pitch;
        collision->tiltRoll =
            collision->tiltRoll +
            ((int)((u32)framesThisStep * ((int)pitch - collision->tiltRoll)) >> 3);
    }
    else
    {
        collision->tiltPitch =
            collision->tiltPitch -
            ((int)((int)collision->tiltPitch * framesThisStep) >> 3);
        collision->tiltRoll =
            collision->tiltRoll -
            ((int)((int)collision->tiltRoll * framesThisStep) >> 3);
        normalZ = lbl_803E0668;
        collision->surfaceNormalX = lbl_803E0668;
        collision->surfaceNormalY = lbl_803E068C;
        collision->surfaceNormalZ = normalZ;
    }
}
#pragma opt_common_subs reset
#pragma dont_inline reset

#pragma dont_inline on
void fn_800E5E38(int obj, CurvesCollisionState* collision)
{
    u32 hitCount;
    int hitIndex;
    f32 currentY;
    f32 window;
    RomCurvePoint* point;

    point = curves_getCurves(obj, collision->points[0][0], collision->points[0][2], &hitCount, 0);
    hitIndex = hitCount - 1;
    currentY = ((GameObject*)obj)->anim.worldPosY;
    window = lbl_803E06A0;
    while (hitIndex >= 0)
    {
        if ((s8)point[hitIndex].type != ROMCURVE_POINT_TYPE_WATER)
        {
            if ((currentY <= point[hitIndex].x) && (currentY >= (point[hitIndex].x - window)))
            {
                ((GameObject*)obj)->anim.worldPosY = point[hitIndex].x;
                collision->surfaceNormalX = point[hitIndex].y;
                collision->surfaceNormalY = point[hitIndex].z;
                collision->surfaceNormalZ = point[hitIndex].w;
                *(s8*)&collision->surfaceFlags |= 0x11;
                collision->surfaceCounter++;
            }
            window = lbl_803E0688;
        }
        hitIndex--;
    }
}
#pragma dont_inline reset

#pragma opt_propagation off
void fn_800E5F1C(int obj, CurvesCollisionState* collision)
{
    int seg;
    int hitCount;
    RomCurvePoint* point;
    int i;
    s8 foundBelow;
    RomCurvePoint* points;
    f32 topSentinel;
    f32 one;
    f32 zero;
    f32 floorSentinel;

    seg = 0;
    topSentinel = gCurvesBoundsMaxSeed;
    floorSentinel = gCurvesBoundsMinSeed;
    zero = lbl_803E0668;
    one = lbl_803E068C;
    points = curves_getCurves(obj, collision->points[0][0], collision->points[0][2], (u32*)&hitCount, 0);
    collision->waterY[0] = topSentinel;
    collision->floorY[0] = topSentinel;
    collision->ceilingY[0] = floorSentinel;
    collision->waterDepth[0] = zero;
    collision->floorGap[0] = zero;
    collision->waterNormalX[0] = zero;
    collision->waterNormalY[0] = one;
    collision->waterNormalZ[0] = zero;
    foundBelow = 0;
    for (i = 0, point = points; i < hitCount; i++)
    {
        if ((s8)point->type != ROMCURVE_POINT_TYPE_WATER)
        {
            if ((foundBelow == 0) && (point->x < (lbl_803E06AC + collision->points[0][1])) &&
                (point->z > gCurvesSurfaceNormalZThreshold))
            {
                collision->floorY[0] = point->x;
                collision->floorGap[0] = collision->points[0][1] - point->x;
                if (collision->segmentHitTypes[0] == -1)
                {
                    *(u8*)&collision->segmentHitTypes[0] = point->type;
                }
                foundBelow = 1;
            }
            else if ((point->x >= (lbl_803E06AC + collision->points[0][1])) && (point->z < lbl_803E0668))
            {
                collision->ceilingY[0] = point->x;
            }
        }
        point++;
    }
    if (foundBelow == 0)
    {
        collision->floorGap[0] = lbl_803E06B0;
    }
    if (((s8)collision->surfaceFlags & (0x10 << seg)) != 0)
    {
        collision->floorGap[0] = lbl_803E0668;
    }
    point = points;
    for (i = 0; i < hitCount; i++)
    {
        if (((s8)point->type == ROMCURVE_POINT_TYPE_WATER) && (point->z > lbl_803E06B4) &&
            (point->x < collision->ceilingY[0]) &&
            (point->x > collision->floorY[0]))
        {
            collision->waterY[0] = point->x;
            collision->waterNormalX[0] = point->y;
            collision->waterNormalY[0] = point->z;
            collision->waterNormalZ[0] = point->w;
        }
        point++;
    }
    if (topSentinel != collision->waterY[0])
    {
        collision->waterDepth[0] = collision->waterY[0] - collision->points[0][1];
    }
    collision->resultWaterY = collision->waterY[0];
    collision->resultFloorY = collision->floorY[0];
    collision->resultCeilingY = collision->ceilingY[0];
    collision->resultWaterDepth = collision->waterDepth[0];
    collision->resultFloorGap = collision->floorGap[0];
}
#pragma opt_propagation reset

#pragma opt_unroll_count 4
void curves_updateLocalPointCollision(int obj, CurvesCollisionState* collision)
{
    u8 pointCount;
    u32 flags;
    f32* localPoint;
    f32* targetRow;
    int zoff[2];
    int pointIndex;
    int mode;
    f32 zero;
    f32 averageScale;
    f32 tempX;
    f32 tempZ;
    CurvesTransformScratch transform;
    f32 matrix[16];

    pointCount = collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK;
    collision->localPointHitMask = zoff[0] = 0;
    pointIndex = 0;
    while (pointIndex < pointCount)
    {
        if ((s32)(collision->flags & 0x200000) != 0)
        {
            mode = 2;
        }
        else
        {
            mode = 4;
        }
        collision->localPointHitMask |= objBboxFn_800640cc(
            collision->localPointTarget[pointIndex], collision->localPointWorld[pointIndex],
            *(f32*)((u8*)collision->localPointRadii + zoff[0]), mode,
            collision->localHitPlanes, obj, collision->primaryHitType, -1, 0,
            (s8)collision->activeTimer) << pointIndex;
        flags = collision->flags;
        if ((s32)(flags & 0x2000000) != 0)
        {
            if ((s32)(flags & 0x200000) != 0)
            {
                mode = 2;
            }
            else
            {
                mode = 4;
            }
            objBboxFn_800640cc(collision->localPointTarget[pointIndex],
                               collision->localPointWorld[pointIndex],
                               *(f32*)((u8*)collision->localPointRadii + zoff[0]), mode,
                               collision->localHitPlanes, obj, collision->secondaryHitType, -1, 0,
                               (s8)collision->activeTimer);
        }
        zoff[0] += sizeof(f32);
        pointIndex++;
    }
    if (pointCount > 1)
    {
        if ((s32)(collision->flags & 0x100000) != 0)
        {
            goto buildTransform;
        }
        zero = lbl_803E0668;
        ((GameObject*)obj)->anim.localPosX = zero;
        ((GameObject*)obj)->anim.localPosZ = zero;
        localPoint = (f32*)collision;
        for (pointIndex = 0; pointIndex < pointCount * 3; pointIndex += 3)
        {
            ((GameObject*)obj)->anim.localPosX += localPoint[57];
            ((GameObject*)obj)->anim.localPosZ += localPoint[59];
            localPoint += 3;
        }
        averageScale = lbl_803E068C / pointCount;
        ((GameObject*)obj)->anim.localPosX *= averageScale;
        ((GameObject*)obj)->anim.localPosZ *= averageScale;
    }
    else if ((s32)(collision->flags & 0x100000) == 0)
    {
        ((GameObject*)obj)->anim.localPosX = collision->localPointWorld[0][0];
        ((GameObject*)obj)->anim.localPosZ = collision->localPointWorld[0][2];
    }
buildTransform:
    transform.angles[0] = ((GameObject*)obj)->anim.rotX;
    if ((s32)(collision->flags & 0x20) != 0)
    {
        transform.angles[1] = 0;
        transform.angles[2] = 0;
    }
    else
    {
        transform.angles[1] = ((GameObject*)obj)->anim.rotY;
        transform.angles[2] = ((GameObject*)obj)->anim.rotZ;
    }
    transform.scale = lbl_803E068C;
    transform.x = ((GameObject*)obj)->anim.localPosX;
    transform.y = ((GameObject*)obj)->anim.localPosY;
    transform.z = ((GameObject*)obj)->anim.localPosZ;
    setMatrixFromObjectPos(matrix, &transform);
    zoff[0] = 0;
    targetRow = (f32*)collision;
    zoff[1] = zoff[0];
    for (; zoff[0] < pointCount * 3; zoff[0] += 3)
    {
        targetRow[69] = targetRow[57];
        targetRow[71] = targetRow[59];
        localPoint = (f32*)((u8*)collision->localPointPositions + zoff[1]);
        Matrix_TransformPoint(matrix, localPoint[0], localPoint[1], localPoint[2], &tempX,
                              &collision->localPointTarget[0][zoff[0] + 1], &tempZ);
        zoff[1] += 0xc;
        targetRow += 3;
    }
}
#pragma opt_unroll_count 0

void curves_preparePointCollisionFrame(int obj, CurvesCollisionState* collision)
{
    extern int ObjHits_IsObjectEnabled(int obj);
    u32 flags;
    int matrixSource;
    int iv[2];
    u8* wb[1];
    int off[1];
    int matrixOffset;
    f32* localPoint;
    f32 resetMin;
    f32 resetRange;
    f32 resetZero;
    CurvesTransformScratch transform;
    f32 matrix[16];

    if ((s32)(collision->flags & CURVES_COLLISION_STATE_ACTIVE) != 0)
    {
        if (*(void**)&((GameObject*)obj)->anim.parent != NULL)
        {
            if ((*(void**)(*(int*)&((GameObject*)obj)->anim.parent + 0x58) != NULL) &&
                (ObjHits_IsObjectEnabled(*(int*)&((GameObject*)obj)->anim.parent) != 0))
            {
                matrixSource = *(int*)(*(int*)&((GameObject*)obj)->anim.parent + 0x58);
                matrixOffset = (*(u8*)(matrixSource + 0x10c) + 2) * 0x10;
                Matrix_TransformPoint((f32*)matrixSource + matrixOffset,
                                      ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                      ((GameObject*)obj)->anim.localPosZ,
                                      &((GameObject*)obj)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosY,
                                      &((GameObject*)obj)->anim.worldPosZ);
            }
            else
            {
                Obj_TransformLocalPointToWorld(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                               ((GameObject*)obj)->anim.localPosZ, &((GameObject*)obj)->anim.worldPosX,
                                               &((GameObject*)obj)->anim.worldPosY, &((GameObject*)obj)->anim.worldPosZ,
                                               *(u32*)&((GameObject*)obj)->anim.parent);
            }
        }
        else
        {
            ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
        }
        flags = collision->flags;
        if ((s32)(flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) != 0)
        {
            transform.angles[0] = ((GameObject*)obj)->anim.rotX;
            if ((s32)(flags & 0x20) != 0)
            {
                transform.angles[1] = 0;
                transform.angles[2] = 0;
            }
            else
            {
                transform.angles[1] = ((GameObject*)obj)->anim.rotY;
                transform.angles[2] = ((GameObject*)obj)->anim.rotZ;
            }
            transform.scale = lbl_803E068C;
            transform.x = ((GameObject*)obj)->anim.worldPosX;
            transform.y = ((GameObject*)obj)->anim.worldPosY;
            transform.z = ((GameObject*)obj)->anim.worldPosZ;
            setMatrixFromObjectPos(matrix, &transform);
            iv[0] = 0;
            iv[1] = iv[0];
            wb[0] = (u8*)collision;
            off[0] = iv[0];
            while (iv[1] < ((int)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT))
            {
                localPoint = (f32*)((u8*)collision->segmentLocalPoints + off[0]);
                Matrix_TransformPoint(matrix, localPoint[0], localPoint[1], localPoint[2],
                                      (f32*)(wb[0] + 8),
                                      &collision->points[0][iv[0] + 1],
                                      &collision->points[0][iv[0] + 2]);
                collision->segmentHitTypes[iv[1]] = -1;
                wb[0] += 0xc;
                off[0] += 0xc;
                iv[0] += 3;
                iv[1]++;
            }
            for (iv[1] = 0;
                 iv[1] < ((int)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT);
                 iv[1]++)
            {
                collision->traceStart[iv[1]][0] = collision->points[iv[1]][0];
                collision->traceStart[iv[1]][1] =
                    lbl_803E06B8 +
                    (collision->points[iv[1]][1] + collision->segmentRadii[iv[1]]);
                collision->traceStart[iv[1]][2] = collision->points[iv[1]][2];
            }
        }
        if (((GameObject*)obj)->anim.classId == 1)
        {
            collision->traceStart[2][0] = collision->points[2][0] = ((GameObject*)obj)->anim.worldPosX;
            collision->traceStart[2][1] = collision->points[2][1] = lbl_803E06BC + ((GameObject*)obj)->anim.worldPosY;
            collision->traceStart[2][2] = collision->points[2][2] = ((GameObject*)obj)->anim.worldPosZ;
        }
        collision->surfaceFlags = 0;
        collision->surfaceHitMask = 0;
        resetRange = gCurvesBoundsMaxSeed;
        collision->resultWaterY = resetRange;
        collision->resultFloorY = resetRange;
        resetMin = gCurvesBoundsMinSeed;
        collision->resultCeilingY = resetMin;
        resetZero = lbl_803E0668;
        collision->resultWaterDepth = resetZero;
        collision->resultFloorGap = resetZero;
        collision->contactObj = 0;
        for (iv[1] = 0;
             iv[1] < ((int)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT);
             iv[1]++)
        {
            collision->waterY[iv[1]] = resetRange;
            collision->floorY[iv[1]] = resetRange;
            collision->ceilingY[iv[1]] = resetMin;
        }
    }
}

void curves_updateLocalPointTransforms(int obj, CurvesCollisionState* collision)
{
    u32 flags;
    u8* wb[1];
    int iv[2];
    int off[1];

    f32* localPoint;
    f32 one;
    CurvesTransformScratch transform;
    f32 matrix[16];

    flags = collision->flags;
    if (((s32)(flags & CURVES_COLLISION_STATE_ACTIVE) != 0) &&
        ((s32)(flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0))
    {
        transform.angles[0] = ((GameObject*)obj)->anim.rotX;
        if ((s32)(flags & 0x20) != 0)
        {
            transform.angles[1] = 0;
            transform.angles[2] = 0;
        }
        else
        {
            transform.angles[1] = ((GameObject*)obj)->anim.rotY;
            transform.angles[2] = ((GameObject*)obj)->anim.rotZ;
        }
        transform.scale = lbl_803E068C;
        transform.x = ((GameObject*)obj)->anim.localPosX;
        transform.y = ((GameObject*)obj)->anim.localPosY;
        transform.z = ((GameObject*)obj)->anim.localPosZ;
        setMatrixFromObjectPos(matrix, &transform);
        iv[0] = 0;
        iv[1] = iv[0];
        wb[0] = (u8*)collision;
        off[0] = iv[0];
        while (iv[1] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK))
        {
            localPoint = (f32*)((u8*)collision->localPointPositions + off[0]);
            Matrix_TransformPoint(matrix, localPoint[0], localPoint[1], localPoint[2],
                                  (f32*)(wb[0] + 228),
                                  &collision->localPointWorld[0][iv[0] + 1],
                                  &collision->localPointWorld[0][iv[0] + 2]);
            wb[0] += 0xc;
            off[0] += 0xc;
            iv[0] += 3;
            iv[1]++;
        }
        iv[0] = 0;
        for (; iv[0] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); iv[0]++)
        {
            *(f32*)((u8*)collision + iv[0] * 12 + 276) = *(f32*)((u8*)collision + iv[0] * 12 + 228);
            *(f32*)((u8*)collision + iv[0] * 12 + 280) = lbl_803E068C + *(f32*)((u8*)collision + iv[0] * 12 + 232);
            *(f32*)((u8*)collision + iv[0] * 12 + 284) = *(f32*)((u8*)collision + iv[0] * 12 + 236);
        }
        fn_80063368((short*)obj);
    }
}

void dll_15_func0A(int obj, CurvesCollisionState* collision)
{
    u32 flags;
    u8* worldBase;
    int zz[3];
    f32* localPoint;
    f32 one;
    CurvesTransformScratch transform;
    f32 matrix[16];

    curves_preparePointCollisionFrame(obj, collision);
    flags = collision->flags;
    if (((s32)(flags & CURVES_COLLISION_STATE_ACTIVE) != 0) &&
        ((s32)(flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0))
    {
        transform.angles[0] = ((GameObject*)obj)->anim.rotX;
        if ((s32)(flags & 0x20) != 0)
        {
            transform.angles[1] = 0;
            transform.angles[2] = 0;
        }
        else
        {
            transform.angles[1] = ((GameObject*)obj)->anim.rotY;
            transform.angles[2] = ((GameObject*)obj)->anim.rotZ;
        }
        transform.scale = lbl_803E068C;
        transform.x = ((GameObject*)obj)->anim.localPosX;
        transform.y = ((GameObject*)obj)->anim.localPosY;
        transform.z = ((GameObject*)obj)->anim.localPosZ;
        setMatrixFromObjectPos(matrix, &transform);
        zz[0] = 0;
        zz[1] = zz[0];
        worldBase = (u8*)collision;
        zz[2] = zz[0];
        while (zz[1] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK))
        {
            localPoint = (f32*)((u8*)collision->localPointPositions + zz[2]);
            Matrix_TransformPoint(matrix, localPoint[0], localPoint[1], localPoint[2],
                                  (f32*)(worldBase + 228),
                                  &collision->localPointWorld[0][zz[0] + 1],
                                  &collision->localPointWorld[0][zz[0] + 2]);
            worldBase += 0xc;
            zz[2] += 0xc;
            zz[0] += 3;
            zz[1]++;
        }
        zz[0] = 0;
        worldBase = (u8*)collision;
        one = lbl_803E068C;
        for (; zz[0] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); zz[0]++)
        {
            *(f32*)(worldBase + 276) = *(f32*)(worldBase + 228);
            *(f32*)(worldBase + 280) = one + *(f32*)(worldBase + 232);
            *(f32*)(worldBase + 284) = *(f32*)(worldBase + 236);
            worldBase += 0xc;
        }
        fn_80063368((short*)obj);
    }
}

f32 dll_15_func0B(int obj, f32 x, f32 baseY, f32 z, f32 height)
{
    int hitCount;
    f32 maxY;
    RomCurvePoint* point;
    int i;
    RomCurvePoint* points;

    points = curves_getCurves(obj, x, z, (u32*)&hitCount, 1);
    i = 0;
    point = points;
    maxY = baseY + height;
    for (; i < hitCount; i++)
    {
        if ((point->x < maxY) && (point->z > *(f32*)&lbl_803E0668))
        {
            return points[i].x;
        }
        point++;
    }
    return baseY;
}

RomCurvePoint*
curves_getCurves(int obj, f32 x, f32 z, u32* outCount, int queryAll)
{
    int queryMode;
    RomCurvePoint* outPoint;
    int pairCount;
    RomCurvePoint** hitPoints;
    RomCurvePoint** hitPointCursor;

    if ((u32)obj != sCurvesCachedHitObj)
    {
        sCurvesCachedHitObj = obj;
        if (queryAll != 0)
        {
            queryMode = 1;
        }
        else
        {
            queryMode = -2;
        }
        sCurvesCachedHitCount = hitDetectFn_80065e50(obj, x, ((GameObject*)obj)->anim.worldPosY, z,
                                                     &hitPoints, queryMode, 0);
        if (ROMCURVE_GETCURVES_MAX_POINTS < (int)sCurvesCachedHitCount)
        {
            sCurvesCachedHitCount = ROMCURVE_GETCURVES_MAX_POINTS;
        }
        hitPointCursor = hitPoints;
        outPoint = sCurvesHitPoints;
        for (pairCount = 0; pairCount < (int)sCurvesCachedHitCount; pairCount++)
        {
            outPoint[pairCount].x = (*hitPointCursor)->x;
            outPoint[pairCount].y = (*hitPointCursor)->y;
            outPoint[pairCount].z = (*hitPointCursor)->z;
            outPoint[pairCount].w = (*hitPointCursor)->w;
            outPoint[pairCount].flags = (*hitPointCursor)->flags;
            outPoint[pairCount].type = (*hitPointCursor)->type;
            hitPointCursor = hitPointCursor + 1;
        }
    }
    *outCount = sCurvesCachedHitCount;
    return sCurvesHitPoints;
}

void dll_15_func08(short* curveObj, CurvesCollisionState* state, u32 updateValue, f32 step)
{
    extern int ObjHits_IsObjectEnabled(int obj);
    int flags;
    CurvesCollisionState* collision;
    f32* pf;
    int byteOff;
    int outOff;
    u8* worldBase;
    int i;
    int worldIdx;
    int linked;
    f32 invStep;
    f32 one;
    f32 zero;
    f32 m1a[16];
    f32 m1b[16];
    f32 m2b[16];
    f32 m2a[16];
    f32 mE[16];
    CurvesTransformScratch s1a;
    CurvesTransformScratch s1b;
    CurvesTransformScratch s2b;
    CurvesTransformScratch s2a;
    CurvesTransformScratch sE;

    collision = state;
    if ((s32)(state->flags & CURVES_COLLISION_STATE_ACTIVE) == 0)
    {
        return;
    }
    one = lbl_803E068C;
    invStep = one / step;
    collision->contactObj = 0;
    if (collision->subtype == CURVES_COLLISION_SUBTYPE_OBJECT)
    {
        sCurvesCachedHitObj = 0;
        sCurvesCachedHitCount = 0;
        zero = lbl_803E0668;
        collision->surfaceNormalX = zero;
        collision->surfaceNormalY = one;
        collision->surfaceNormalZ = zero;
        if (((s32)(state->flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0) &&
            ((collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK) != 0))
        {
            s1a.angles[0] = curveObj[0];
            if ((s32)(state->flags & 0x20) != 0)
            {
                s1a.angles[1] = 0;
                s1a.angles[2] = 0;
            }
            else
            {
                s1a.angles[1] = curveObj[1];
                s1a.angles[2] = curveObj[2];
            }
            s1a.scale = lbl_803E068C;
            s1a.x = ((GameObject*)curveObj)->anim.localPosX;
            s1a.y = ((GameObject*)curveObj)->anim.localPosY;
            s1a.z = ((GameObject*)curveObj)->anim.localPosZ;
            setMatrixFromObjectPos(m1a, &s1a);
            worldIdx = i = 0;
            worldBase = (u8*)collision;
            byteOff = 0;
            while (i < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK))
            {
                pf = (f32*)((u8*)collision->localPointPositions + byteOff);
                Matrix_TransformPoint(m1a, pf[0], pf[1], pf[2],
                                      (f32*)(worldBase + 228),
                                      &collision->localPointWorld[0][worldIdx + 1],
                                      &collision->localPointWorld[0][worldIdx + 2]);
                worldBase += 0xc;
                byteOff += 0xc;
                worldIdx += 3;
                i++;
            }
            curves_updateLocalPointCollision((int)curveObj, collision);
            if (*(void**)(curveObj + 0x18) != NULL)
            {
                if ((*(void**)(*(int*)(curveObj + 0x18) + 0x58) != NULL) &&
                    (ObjHits_IsObjectEnabled(*(int*)(curveObj + 0x18)) != 0))
                {
                    outOff = (*(u8*)(*(int*)(*(int*)(curveObj + 0x18) + 0x58) + 0x10c) + 2) * 0x10;
                    Matrix_TransformPoint((f32*)(*(int*)(*(int*)(curveObj + 0x18) + 0x58)) +
                                          outOff,
                                          ((GameObject*)curveObj)->anim.localPosX, ((GameObject*)curveObj)->anim.localPosY, ((GameObject*)curveObj)->anim.localPosZ,
                                          (f32*)(curveObj + 0xc), (f32*)(curveObj + 0xe), (f32*)(curveObj + 0x10));
                }
                else
                {
                    Obj_TransformLocalPointToWorld(((GameObject*)curveObj)->anim.localPosX, ((GameObject*)curveObj)->anim.localPosY,
                                                   ((GameObject*)curveObj)->anim.localPosZ, (f32*)(curveObj + 0xc),
                                                   (f32*)(curveObj + 0xe), (f32*)(curveObj + 0x10),
                                                   *(u32*)(curveObj + 0x18));
                }
            }
            else
            {
                ((GameObject*)curveObj)->anim.worldPosX = ((GameObject*)curveObj)->anim.localPosX;
                ((GameObject*)curveObj)->anim.worldPosY = ((GameObject*)curveObj)->anim.localPosY;
                ((GameObject*)curveObj)->anim.worldPosZ = ((GameObject*)curveObj)->anim.localPosZ;
            }
        }
        if (((s32)(state->flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) != 0) &&
            ((collision->pointCounts & CURVES_POINT_COUNT_SEGMENT_MASK) != 0))
        {
            s1b.angles[0] = curveObj[0];
            if ((s32)(state->flags & 0x20) != 0)
            {
                s1b.angles[1] = 0;
                s1b.angles[2] = 0;
            }
            else
            {
                s1b.angles[1] = curveObj[1];
                s1b.angles[2] = curveObj[2];
            }
            s1b.scale = lbl_803E068C;
            s1b.x = ((GameObject*)curveObj)->anim.worldPosX;
            s1b.y = ((GameObject*)curveObj)->anim.worldPosY;
            s1b.z = ((GameObject*)curveObj)->anim.worldPosZ;
            setMatrixFromObjectPos(m1b, &s1b);
            worldIdx = 0;
            i = worldIdx;
            worldBase = (u8*)collision;
            byteOff = worldIdx;
            for (; i < (int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT; i++)
            {
                pf = (f32*)((u8*)collision->segmentLocalPoints + byteOff);
                Matrix_TransformPoint(m1b, pf[0], pf[1], pf[2],
                                      (f32*)(worldBase + 8),
                                      &collision->points[0][worldIdx + 1],
                                      &collision->points[0][worldIdx + 2]);
                collision->segmentHitTypes[i] = -1;
                worldBase += 0xc;
                byteOff += 0xc;
                worldIdx += 3;
            }
            if ((s32)(state->flags & 2) != 0)
            {
                *(char*)&collision->surfaceFlags = hitDetectFn_80067958((int)curveObj,
                                                                        collision->traceStart,
                                                                        collision->points,
                                                                        (int)(u32)collision->pointCounts >>
                                                                        CURVES_POINT_COUNT_SEGMENT_SHIFT,
                                                                        collision->segmentHitPlanes, 0);
                *(s8*)&collision->surfaceCounter = collision->traceHitCount;
                collision->surfaceHitMask = 0;
            }
            switch (collision->updateMode)
            {
            case 3:
                curves_countRandomPoints((int)curveObj, collision);
                break;
            case 1:
                fn_800E56A4((int)curveObj, collision);
                break;
            case 4:
                collision->surfaceNormalX = collision->segmentHitPlanes[0][0];
                collision->surfaceNormalY = collision->segmentHitPlanes[0][1];
                collision->surfaceNormalZ = collision->segmentHitPlanes[0][2];
                if (((collision->surfaceFlags & 1) != 0) && (collision->segmentHitTypes[0] == 0x21))
                {
                    ((GameObject*)curveObj)->anim.worldPosX = collision->points[0][0];
                    ((GameObject*)curveObj)->anim.worldPosY = collision->points[0][1];
                    ((GameObject*)curveObj)->anim.worldPosZ = collision->points[0][2];
                }
                break;
            default:
                fn_800E58FC((int)curveObj, collision);
                break;
            }
            if ((s32)(state->flags & 0x100) != 0)
            {
                fn_800E5E38((int)curveObj, collision);
            }
            if ((s32)(state->flags & 0x80) != 0)
            {
                fn_800E5CBC((short*)curveObj, (int)state);
            }
            if ((s32)(state->flags & 1) != 0)
            {
                fn_800E5F1C((int)curveObj, collision);
            }
            memcpy(collision->traceStart, collision->points,
                   ((int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT) * 0xc);
        }
        if ((s32)(state->flags & 0x800) != 0)
        {
            if (0x3400 < curveObj[1])
            {
                curveObj[1] = 0x3400;
            }
            if (curveObj[1] < -0x3400)
            {
                curveObj[1] = -0x3400;
            }
        }
        if ((s32)(state->flags & 0x1000) != 0)
        {
            if (0x3400 < curveObj[2])
            {
                curveObj[2] = 0x3400;
            }
            if (curveObj[2] < -0x3400)
            {
                curveObj[2] = -0x3400;
            }
        }
        if ((s32)(state->flags & 0x40000) == 0)
        {
            linked = *(int*)(curveObj + 0x2a);
            if (((void*)linked != NULL) && ((*(s16*)&((GameObject*)linked)->anim.eventTable & 1) != 0))
            {
                ((GameObject*)curveObj)->anim.velocityY =
                    invStep * (((GameObject*)curveObj)->anim.worldPosY - ((GameObject*)linked)->anim.worldPosZ);
                if (((GameObject*)curveObj)->anim.worldPosY > *(f32*)(*(int*)(curveObj + 0x2a) + 0x20))
                {
                    ((GameObject*)curveObj)->anim.velocityY = lbl_803E0668;
                }
            }
            else
            {
                ((GameObject*)curveObj)->anim.velocityY =
                    invStep * (((GameObject*)curveObj)->anim.worldPosY - *(f32*)(curveObj + 0x48));
            }
        }
    }
    else if (collision->subtype == CURVES_COLLISION_SUBTYPE_POINT)
    {
        curves_preparePointCollisionFrame((int)curveObj, collision);
        flags = state->flags;
        if (((flags & CURVES_COLLISION_STATE_ACTIVE) != 0) &&
            ((flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0))
        {
            s2a.angles[0] = curveObj[0];
            if ((flags & 0x20) != 0)
            {
                s2a.angles[1] = 0;
                s2a.angles[2] = 0;
            }
            else
            {
                s2a.angles[1] = curveObj[1];
                s2a.angles[2] = curveObj[2];
            }
            s2a.scale = lbl_803E068C;
            s2a.x = ((GameObject*)curveObj)->anim.localPosX;
            s2a.y = ((GameObject*)curveObj)->anim.localPosY;
            s2a.z = ((GameObject*)curveObj)->anim.localPosZ;
            setMatrixFromObjectPos(m2a, &s2a);
            worldIdx = 0;
            i = worldIdx;
            worldBase = (u8*)collision;
            byteOff = worldIdx;
            while (i < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK))
            {
                pf = (f32*)((u8*)collision->localPointPositions + byteOff);
                Matrix_TransformPoint(m2a, pf[0], pf[1], pf[2],
                                      (f32*)(worldBase + 228),
                                      &collision->localPointWorld[0][worldIdx + 1],
                                      &collision->localPointWorld[0][worldIdx + 2]);
                worldBase += 0xc;
                byteOff += 0xc;
                worldIdx += 3;
                i++;
            }
            for (i = 0; i < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); i++)
            {
                collision->localPointTarget[i][0] = collision->localPointWorld[i][0];
                collision->localPointTarget[i][1] = lbl_803E068C + collision->localPointWorld[i][1];
                collision->localPointTarget[i][2] = collision->localPointWorld[i][2];
            }
            fn_80063368(curveObj);
        }
        if ((s32)(state->flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) != 0)
        {
            s2b.angles[0] = curveObj[0];
            if ((s32)(state->flags & 0x20) != 0)
            {
                s2b.angles[1] = 0;
                s2b.angles[2] = 0;
            }
            else
            {
                s2b.angles[1] = curveObj[1];
                s2b.angles[2] = curveObj[2];
            }
            s2b.scale = lbl_803E068C;
            s2b.x = ((GameObject*)curveObj)->anim.worldPosX;
            s2b.y = ((GameObject*)curveObj)->anim.worldPosY;
            s2b.z = ((GameObject*)curveObj)->anim.worldPosZ;
            setMatrixFromObjectPos(m2b, &s2b);
            worldIdx = 0;
            i = worldIdx;
            worldBase = (u8*)collision;
            byteOff = worldIdx;
            for (; i < (int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT; i++)
            {
                pf = (f32*)((u8*)collision->segmentLocalPoints + byteOff);
                Matrix_TransformPoint(m2b, pf[0], pf[1], pf[2],
                                      (f32*)(worldBase + 8),
                                      &collision->points[0][worldIdx + 1],
                                      &collision->points[0][worldIdx + 2]);
                collision->segmentHitTypes[i] = -1;
                worldBase += 0xc;
                byteOff += 0xc;
                worldIdx += 3;
            }
            memcpy(collision->traceStart, collision->points,
                   ((int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT) * 0xc);
            if ((s32)(state->flags & 1) != 0)
            {
                fn_800E5F1C((int)curveObj, collision);
            }
        }
    }
    else
    {
        curves_preparePointCollisionFrame((int)curveObj, collision);
        flags = state->flags;
        if (((flags & CURVES_COLLISION_STATE_ACTIVE) != 0) &&
            ((flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0))
        {
            sE.angles[0] = curveObj[0];
            if ((flags & 0x20) != 0)
            {
                sE.angles[1] = 0;
                sE.angles[2] = 0;
            }
            else
            {
                sE.angles[1] = curveObj[1];
                sE.angles[2] = curveObj[2];
            }
            sE.scale = lbl_803E068C;
            sE.x = ((GameObject*)curveObj)->anim.localPosX;
            sE.y = ((GameObject*)curveObj)->anim.localPosY;
            sE.z = ((GameObject*)curveObj)->anim.localPosZ;
            setMatrixFromObjectPos(mE, &sE);
            worldIdx = 0;
            i = worldIdx;
            worldBase = (u8*)collision;
            byteOff = worldIdx;
            while (i < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK))
            {
                pf = (f32*)((u8*)collision->localPointPositions + byteOff);
                Matrix_TransformPoint(mE, pf[0], pf[1], pf[2],
                                      (f32*)(worldBase + 228),
                                      &collision->localPointWorld[0][worldIdx + 1],
                                      &collision->localPointWorld[0][worldIdx + 2]);
                worldBase += 0xc;
                byteOff += 0xc;
                worldIdx += 3;
                i++;
            }
            for (i = 0; i < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); i++)
            {
                collision->localPointTarget[i][0] = collision->localPointWorld[i][0];
                collision->localPointTarget[i][1] = lbl_803E068C + collision->localPointWorld[i][1];
                collision->localPointTarget[i][2] = collision->localPointWorld[i][2];
            }
            fn_80063368(curveObj);
        }
    }
    if (*(void**)(curveObj + 0x18) != NULL)
    {
        if ((*(void**)(*(int*)(curveObj + 0x18) + 0x58) != NULL) &&
            (ObjHits_IsObjectEnabled(*(int*)(curveObj + 0x18)) != 0))
        {
            outOff = (u32) * (u8*)(*(int*)(*(int*)(curveObj + 0x18) + 0x58) + 0x10c) * 0x10;
            Matrix_TransformPoint((f32*)(*(int*)(*(int*)(curveObj + 0x18) + 0x58)) + outOff,
                                  ((GameObject*)curveObj)->anim.worldPosX, ((GameObject*)curveObj)->anim.worldPosY, ((GameObject*)curveObj)->anim.worldPosZ,
                                  (f32*)(curveObj + 6), (f32*)(curveObj + 8), (f32*)(curveObj + 10));
        }
        else
        {
            Obj_TransformWorldPointToLocal(((GameObject*)curveObj)->anim.worldPosX, ((GameObject*)curveObj)->anim.worldPosY,
                                           ((GameObject*)curveObj)->anim.worldPosZ, (f32*)(curveObj + 6),
                                           (f32*)(curveObj + 8), (f32*)(curveObj + 10),
                                           *(u32*)(curveObj + 0x18));
        }
    }
    else
    {
        ((GameObject*)curveObj)->anim.localPosX = ((GameObject*)curveObj)->anim.worldPosX;
        ((GameObject*)curveObj)->anim.localPosY = ((GameObject*)curveObj)->anim.worldPosY;
        ((GameObject*)curveObj)->anim.localPosZ = ((GameObject*)curveObj)->anim.worldPosZ;
    }
}

void dll_15_func06(GameObject* obj, CurvesCollisionState* state)
{
    extern int ObjHits_IsObjectEnabled(int obj);
    f32 maxX;
    f32 minX;
    f32 r;
    f32 v;
    f32 minY;
    f32 maxZ;
    f32 minZ;
    f32 maxY;
    f32* pin;
    int idx3;
    int byteOff;
    int n;
    CurvesCollisionState* radSrc;
    f32 c;
    f32* radDst;
    f32* radWrite;
    f32* ptsRead;
    int i;
    f32* ptsWalk;
    f32 m[16];
    f32 pts[12];
    CurvesTransformScratch s;
    f32 radii[4];

    if (state->subtype == CURVES_COLLISION_SUBTYPE_NONE ||
        (s32)(state->flags & CURVES_COLLISION_STATE_ACTIVE) == 0 ||
        (s32)(state->flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) == 0)
    {
        return;
    }
    {
        if (*(void**)&obj->anim.parent != NULL)
        {
            if ((*(void**)(*(int*)&obj->anim.parent + 0x58) != NULL) &&
                (ObjHits_IsObjectEnabled(*(int*)&obj->anim.parent) != 0))
            {
                idx3 = (*(u8*)(*(int*)(*(int*)&obj->anim.parent + 0x58) + 0x10c) + 2) * 0x10;
                Matrix_TransformPoint((f32*)(*(int*)(*(int*)&obj->anim.parent + 0x58)) + idx3,
                                      obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                      &obj->anim.worldPosX, &obj->anim.worldPosY, &obj->anim.worldPosZ);
            }
            else
            {
                Obj_TransformLocalPointToWorld(obj->anim.localPosX,
                                               obj->anim.localPosY,
                                               obj->anim.localPosZ,
                                               &obj->anim.worldPosX,
                                               &obj->anim.worldPosY,
                                               &obj->anim.worldPosZ,
                                               *(u32*)&obj->anim.parent);
            }
        }
        else
        {
            obj->anim.worldPosX = obj->anim.localPosX;
            obj->anim.worldPosY = obj->anim.localPosY;
            obj->anim.worldPosZ = obj->anim.localPosZ;
        }
        s.angles[0] = obj->anim.rotX;
        if ((s32)(state->flags & 0x20) != 0)
        {
            s.angles[1] = 0;
            s.angles[2] = 0;
        }
        else
        {
            s.angles[1] = obj->anim.rotY;
            s.angles[2] = obj->anim.rotZ;
        }
        s.scale = lbl_803E068C;
        s.x = obj->anim.worldPosX;
        s.y = obj->anim.worldPosY;
        s.z = obj->anim.worldPosZ;
        setMatrixFromObjectPos(m, &s);
        idx3 = 0;
        i = 0;
        ptsRead = pts;
        ptsWalk = ptsRead;
        byteOff = 0;
        radSrc = state;
        radWrite = radii;
        radDst = radii;
        c = lbl_803E06C0;
        for (; i < (int)(u32)state->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT; i++)
        {
            pin = (f32*)((u8*)state->segmentLocalPoints + byteOff);
            Matrix_TransformPoint(m, pin[0], pin[1], pin[2], ptsWalk,
                                  pts + (idx3 + 1), pts + (idx3 + 2));
            *radDst = radSrc->segmentRadii[0];
            *radDst = sqrtf((c * *radDst) * *radDst);
            ptsWalk = ptsWalk + 3;
            byteOff = byteOff + 0xc;
            idx3 = idx3 + 3;
            radSrc = (CurvesCollisionState*)((u8*)radSrc + 4);
            radDst = radDst + 1;
        }
        maxX = gCurvesBoundsMaxSeed;
        minX = gCurvesBoundsMinSeed;
        maxY = maxX;
        minY = minX;
        maxZ = maxX;
        minZ = minX;
        for (n = 0; n < ((int)(u32)state->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT); n++)
        {
            v = *ptsRead + (r = *radWrite);
            if (v > maxX)
            {
                maxX = v;
            }
            v = *ptsRead - r;
            if (v < minX)
            {
                minX = v;
            }
            v = ptsRead[1] + r;
            if (v > maxY)
            {
                maxY = v;
            }
            v = ptsRead[1] - r;
            if (v < minY)
            {
                minY = v;
            }
            v = ptsRead[2] + r;
            if (v > maxZ)
            {
                maxZ = v;
            }
            v = ptsRead[2] - r;
            if (v < minZ)
            {
                minZ = v;
            }
            v = state->traceStart[n][0] + r;
            if (v > maxX)
            {
                maxX = v;
            }
            v = state->traceStart[n][0] - r;
            if (v < minX)
            {
                minX = v;
            }
            v = state->traceStart[n][1] + r;
            if (v > maxY)
            {
                maxY = v;
            }
            v = state->traceStart[n][1] - r;
            if (v < minY)
            {
                minY = v;
            }
            v = state->traceStart[n][2] + r;
            if (v > maxZ)
            {
                maxZ = v;
            }
            r = state->traceStart[n][2] - r;
            if (r < minZ)
            {
                minZ = r;
            }
            ptsRead = ptsRead + 3;
            radWrite = radWrite + 1;
        }
        state->hitBounds[0] = minX;
        state->hitBounds[3] = maxX;
        state->hitBounds[1] = (int)(minY - state->heightPadding);
        state->hitBounds[4] = (int)(maxY + state->heightPadding);
        state->hitBounds[2] = minZ;
        state->hitBounds[5] = maxZ;
    }
}

#pragma opt_unroll_count 8
void dll_15_func05(CurvesCollisionState* state, int count, f32* segmentLocalPoints, f32* radii,
                   s8* types)
{
    int i;

    state->pointCounts &= CURVES_POINT_COUNT_LOCAL_MASK;
    state->pointCounts |= (count & CURVES_POINT_COUNT_LOCAL_MASK) << CURVES_POINT_COUNT_SEGMENT_SHIFT;
    state->segmentLocalPoints = segmentLocalPoints;
    for (i = 0; i < count; i++)
    {
        state->segmentSourceTypes[i] = (s8)types[i];
        state->segmentHitTypes[i] = -1;
        state->segmentRadii[i] = radii[i];
    }
    state->flags |= CURVES_COLLISION_STATE_HIT_SEGMENTS;
}
#pragma opt_unroll_count 0

void dll_15_func07(void* arg1, CurvesCollisionState* state)
{
    u32 flags;
    s8 type;
    u8 mask;
    mask = 0;
    flags = state->flags;
    if ((s32)(flags & CURVES_COLLISION_STATE_ACTIVE) == 0 ||
        (s32)(flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) == 0)
    {
        return;
    }
    type = state->subtype;
    if (type == CURVES_COLLISION_SUBTYPE_OBJECT || type == CURVES_COLLISION_SUBTYPE_POINT)
    {
        if ((s32)(flags & 0x00000004) != 0) mask |= 0x1;
        if ((s32)(flags & 0x01000000) != 0) mask |= 0x20;
        hitDetectFn_800691c0(arg1, state->hitBounds, mask, 1);
    }
}

void curves_setLocalPointCollisionEx(CurvesCollisionState* state, int pointCount,
                                     f32* localPointPositions, f32* localPointRadii,
                                     int primaryHitType, int secondaryHitType)
{
    state->pointCounts &= CURVES_POINT_COUNT_SEGMENT_MASK;
    state->pointCounts = (u8)(state->pointCounts | (pointCount & CURVES_POINT_COUNT_LOCAL_MASK));
    state->primaryHitType = primaryHitType;
    state->secondaryHitType = secondaryHitType;
    state->localPointPositions = localPointPositions;
    state->localPointRadii = localPointRadii;
    state->flags |= CURVES_COLLISION_STATE_SECONDARY_LOCAL_POINTS | CURVES_COLLISION_STATE_LOCAL_POINTS;
    state->activeTimer = 0xa;
}

void dll_15_func04(CurvesCollisionState* state, int pointCount, f32* localPointPositions,
                   f32* localPointRadii, int primaryHitType)
{
    state->pointCounts &= CURVES_POINT_COUNT_SEGMENT_MASK;
    state->pointCounts = (u8)(state->pointCounts | (pointCount & CURVES_POINT_COUNT_LOCAL_MASK));
    state->primaryHitType = primaryHitType;
    state->localPointPositions = localPointPositions;
    state->localPointRadii = localPointRadii;
    state->flags |= CURVES_COLLISION_STATE_LOCAL_POINTS;
    state->activeTimer = 0xa;
}

void curves_clear(CurvesCollisionState* state, int updateMode, u32 flags, int subtype)
{
    memset(state, 0, CURVES_COLLISION_STATE_SIZE);
    state->subtype = subtype;
    state->flags = flags | CURVES_COLLISION_STATE_ACTIVE;
    state->updateMode = updateMode;
    state->heightPadding = 5;
}

u32 playerHasKrazoaSpirit(u8 checkStoryBits, u32 bit)
{
    if (checkStoryBits == 0)
    {
        return GameBit_Get(bit);
    }
    if ((GameBit_Get(0xbfd) != 0) || (GameBit_Get(0xff) != 0) ||
        (GameBit_Get(GAMEBIT_K1_SPIRIT_COLLECTED) != 0) || (GameBit_Get(0xc85) != 0) ||
        (GameBit_Get(0xc6e) != 0) || (GameBit_Get(0x174) != 0))
    {
        return 1;
    }
    return 0;
}

void saveFileStruct_setCheatActive(u8 optionIndex, u8 active)
{
    SaveData* save;

    save = &saveData;
    if ((save->registeredDebugOptions & (1 << optionIndex)) == 0)
    {
        return;
    }
    if (active != 0)
    {
        save->enabledDebugOptions |= 1 << optionIndex;
    }
    else
    {
        save->enabledDebugOptions = save->enabledDebugOptions & ~(1 << optionIndex);
    }
}

void dll_15_release_nop(void)
{
}

void dll_15_initialise_nop(void)
{
}

void loadSaveSettings(void)
{
    setWidescreen(saveData.widescreenEnabled);
    setSubtitlesEnabled(saveData.subtitlesEnabled);
    setRumbleEnabled(saveData.rumbleEnabled);
    audioSetSoundMode(saveData.soundMode, 0);
    (*gGameUIInterface)->setUnusedHudSetting(saveData.gameUiSetting);
    (*gCameraInterface)->func1D(saveData.cameraSetting);
    audioSetVolumes(saveData.sfxVolume, 10, 0, 1, 0);
    audioSetVolumes(saveData.musicVolume, 10, 1, 0, 0);
    audioSetVolumes(saveData.speechVolume, 10, 0, 0, 1);
}

void* getSaveFileStruct(void) { return &saveData; }

void* getLastSavedGameTexts(void) { return gSaveGameData + 0x558; }

#define SAVEGAME_OBJECT_POSITION_COUNT 0x3f
#define SAVEGAME_OBJECT_POSITION_OFFSET 0x168

typedef struct CurvesSaveGameObjectPosition
{
    u32 objectId;
    f32 x;
    f32 y;
    f32 z;
} CurvesSaveGameObjectPosition;

int pushable_savePos(int obj)
{
    int i;
    CurvesSaveGameObjectPosition* position;
    u32 objectId;
    f32 savedX;

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++)
    {
        position = &((CurvesSaveGameObjectPosition*)gSaveGameData)[i];
        objectId = ((RomCurveDef*)((GameObject*)obj)->anim.placementData)->id;
        if (objectId == *(u32*)((u8*)&position->objectId + SAVEGAME_OBJECT_POSITION_OFFSET))
        {
            if ((((GameObject*)obj)->anim.localPosX ==
                    (savedX = *(f32*)((int)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 4 + (i << 4)))) &&
                (((GameObject*)obj)->anim.localPosY ==
                    *(f32*)((int)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 8 + (i << 4))) &&
                (((GameObject*)obj)->anim.localPosZ ==
                    *(f32*)((int)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 0xc + (i << 4))))
            {
                return 0;
            }
            ((GameObject*)obj)->anim.localPosX = savedX;
            ((GameObject*)obj)->anim.localPosY = *(f32*)((u32)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 8 + (i << 4));
            ((GameObject*)obj)->anim.localPosZ = *(f32*)((u32)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 0xc + (i << 4));
            return 1;
        }
    }
    return 0;
}

void saveFileStruct_resetVolumes(void)
{
    saveData.musicVolume = 0x7f;
    saveData.sfxVolume = 0x7f;
    saveData.speechVolume = 0x7f;
}

int isCheatUnlocked(u8 idx)
{
    SaveData* p = &saveData;
    u32 reg = p->registeredDebugOptions;
    u32 mask = 1 << idx;
    return reg & mask;
}

void saveFileStruct_unlockCheat(u8 idx)
{
    SaveData* p = &saveData;
    u32 reg = p->registeredDebugOptions;
    u32 mask = 1 << idx;
    p->registeredDebugOptions = reg | mask;
}

int saveFileStruct_isCheatActive(u8 idx)
{
    SaveData* save;

    save = &saveData;
    if ((save->registeredDebugOptions & (1 << idx)) != 0)
    {
        if ((save->enabledDebugOptions & (1 << idx)) != 0)
        {
            return 1;
        }
    }
    return 0;
}
