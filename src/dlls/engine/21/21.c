#include "dolphin/os.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "dlls/object_descriptor.h"
#include "main/game_ui_interface.h"
#include "main/lightmap_api.h"
#include "main/textrender_api.h"
#include "main/objhits.h"
#include "game/objects/object.h"
#include "string.h"
#define TRACK_BBOX_ARG10_TYPE int
#include "main/track_bbox_api.h"
#include "main/gamebits.h"
#include "main/object_transform.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/frame_timing.h"
#include "main/audio/audio_control_api.h"
#include "main/pad.h"
#include "main/dll/rom_curve_def.h"

GameObject* sCurvesCachedHitObj;
s32 sCurvesCachedHitCount;

#define CURVES_ONE                        1.0f
#define CURVES_SURFACE_NORMAL_Z_THRESHOLD 0.707f
#define CURVES_RAISED_TRACE_OFFSET        18.0f
#define CURVES_HIT_SCRATCH_SCALE          7.5f
#define CURVES_MAX_SEGMENT_DISTANCE       30.0f
#define CURVES_VERTICAL_TRACE_DISTANCE    20.0f
#define CURVES_HALF                       0.5f
#define CURVES_DEFAULT_VERTICAL_WINDOW    10000.0f
#define CURVES_BOUNDS_MAX_SEED            -100000.0f
#define CURVES_BOUNDS_MIN_SEED            100000.0f
#define CURVES_SURFACE_EPSILON            5.0f
#define CURVES_NO_FLOOR_GAP               100.0f
#define CURVES_WATER_NORMAL_THRESHOLD     0.9f
#define CURVES_TRACE_RADIUS_OFFSET        0.1f
#define CURVES_FALLBACK_TRACE_HEIGHT      35.0f
#define CURVES_RADIUS_SCALE               2.0f

TrackGroundHit sCurvesHitPoints[ROMCURVE_GETCURVES_MAX_POINTS];

static inline u32 RomCurve_GetId(RomCurveDef* curve) {
    return curve->id;
}

static inline int RomCurve_IsLinkIdValid(int linkId) {
    return -1 < linkId;
}

static inline RomCurveDef* RomCurve_FindByIdInline(u32 curveId) {
    RomCurveDef* curve;
    int high;
    int low;
    int mid;

    if ((s32)curveId < 0) {
        return NULL;
    }

    high = nRomCurves - 1;
    low = 0;
    while (high >= low) {
        mid = (high + low) >> 1;
        curve = romCurves[mid];
        if (curveId > curve->id) {
            low = mid + 1;
        } else if (curveId < curve->id) {
            high = mid - 1;
        } else {
            return curve;
        }
    }

    return NULL;
}

static inline int RomCurve_noForwardLinks(RomCurveDef* curve) {
    int bit;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++) {
        if ((s32)curve->linkIds[bit] != -1 && (curve->backwardLinkMask & (1 << bit)) == 0) {
            return 0;
        }
    }
    return 1;
}

static inline int RomCurve_noBackwardLinks(RomCurveDef* curve) {
    int bit;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++) {
        if ((s32)curve->linkIds[bit] != -1 && (curve->backwardLinkMask & (1 << bit)) != 0) {
            return 0;
        }
    }
    return 1;
}

void curves_countRandomPoints(GameObject* obj, CurvesCollisionState* collision) {
    GameObject* object;
    TrackGroundHit** list;
    int found1;
    int hits;
    TrackGroundHit* point;
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
    TrackGroundHit** hitOut;
    f32 heights[5];

    object = obj;
    if ((int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT == 4) {
        sum0 = 0.0f;
        count = 0;
        sum3 = sum2 = sum1 = sum0;
        for (i = 0; i < (int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT; i++) {
            heights[i] = collision->points[i][1];
            hits = trackGetHeight(obj, collision->points[i][0], object->anim.worldPosY, collision->points[i][2],
                                  &hitOut, -1, 0);
            found1 = 0;
            if (hits != 0) {
                list = hitOut;
                for (j = 0; j < hits; j++) {
                    if (!found1) {
                        point = *list;
                        pointY = point->height;
                        if ((pointY < 50.0f + object->anim.worldPosY) &&
                            ((s8)point->surfaceType != ROMCURVE_POINT_TYPE_WATER)) {
                            heights[i] = point->height;
                            sum1 = sum1 + point->normalX;
                            sum2 = sum2 + point->normalY;
                            sum3 = sum3 + point->normalZ;
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
        if (count != 0) {
            object->anim.worldPosY = sum0 / (f32)(s32)count;
            collision->surfaceNormalX = sum1 / (f32)(s32)count;
            collision->surfaceNormalY = sum2 / (f32)(s32)count;
            collision->surfaceNormalZ = sum3 / (f32)(s32)count;
            collision->surfaceCounter = 1;
        } else {
            collision->surfaceCounter = 0;
        }
        dx = heights[3];
        dz = collision->segmentLocalPoints[11];
        dz = dz - collision->segmentLocalPoints[2];
        dx = dx - heights[0];
        getAngle(dx, dz);
        ang = getAngle(dx, dz);
        object->anim.rotY = -ang;
        if (((int)collision->flags & 0x400) != 0) {
            dx = heights[1];
            dz = collision->segmentLocalPoints[3] - collision->segmentLocalPoints[0];
            dx = dx - heights[0];
            object->anim.rotZ = getAngle(dx, dz);
        }
    }
}

void curves_resolveSingleTrace(GameObject* obj, CurvesCollisionState* collision) {
    TrackGroundHit* point;
    TrackGroundHit* points;
    int hitCount;
    int count;
    int pointIndex;
    Vec delta;
    TrackHitResults hitScratch;
    f32 startX;
    f32 startZ;

    startX = collision->points[1][0];
    startZ = collision->points[1][2];
    if ((s32)(collision->flags & CURVES_COLLISION_STATE_KEEP_POSITION) == 0) {
        (obj)->anim.worldPosX = startX;
        (obj)->anim.worldPosZ = startZ;
        (obj)->anim.worldPosY = collision->points[0][1];
    }

    points = curves_getCurves(obj, collision->points[1][0], collision->points[1][2], (u32*)&hitCount, 0);
    for (pointIndex = 0, point = points, count = hitCount; pointIndex < count;) {
        if (((s8)point->surfaceType != ROMCURVE_POINT_TYPE_WATER) &&
            (point->normalY > CURVES_SURFACE_NORMAL_Z_THRESHOLD) && (point->height <= collision->points[1][1]) &&
            (point->height > collision->points[0][1])) {
            collision->traceStart[0][0] = collision->points[1][0];
            collision->traceStart[0][1] = collision->points[1][1];
            collision->traceStart[0][2] = collision->points[1][2];
            collision->points[0][0] = collision->points[1][0];
            collision->points[0][1] = points[pointIndex].height;
            collision->points[0][2] = collision->points[1][2];
            trackGetIntersect(obj, collision->traceStart[0], collision->points[0], 1, collision->segmentHits.planes, 0);
            break;
        }
        point++;
        pointIndex++;
    }

    if ((obj)->anim.classId == 1) {
        collision->traceStart[2][0] = collision->points[1][0];
        collision->traceStart[2][1] = collision->points[1][1];
        collision->traceStart[2][2] = collision->points[1][2];
        collision->points[2][0] = collision->points[1][0];
        collision->points[2][1] = CURVES_RAISED_TRACE_OFFSET + collision->points[1][1];
        collision->points[2][2] = collision->points[1][2];
        hitScratch.radii[0] = CURVES_HIT_SCRATCH_SCALE;
        hitScratch.queryTypes[0] = 3;
        trackGetIntersect(obj, collision->traceStart[2], collision->points[2], 1, &hitScratch, 0);
    }

    PSVECSubtract((Vec*)collision->points[0], (Vec*)collision->points[1], &delta);
    if (((s32)(collision->flags & 0x8000000) != 0) || (PSVECMag(&delta) > CURVES_MAX_SEGMENT_DISTANCE)) {
        collision->traceStart[0][0] = collision->points[1][0];
        collision->traceStart[0][1] = collision->points[1][1];
        collision->traceStart[0][2] = collision->points[1][2];
        collision->points[0][0] = collision->points[1][0];
        collision->points[0][1] = collision->points[1][1] - CURVES_VERTICAL_TRACE_DISTANCE;
        collision->points[0][2] = collision->points[1][2];
        trackGetIntersect(obj, collision->traceStart[0], collision->points[0], 1, collision->segmentHits.planes, 0);
    }

    collision->surfaceNormalX = collision->segmentHits.planes[0][0];
    collision->surfaceNormalY = collision->segmentHits.planes[0][1];
    collision->surfaceNormalZ = collision->segmentHits.planes[0][2];
    collision->contactObj = collision->segmentHits.objects[0];
    if (collision->contactObj != 0) {
        ObjHits_AddContactObject(collision->contactObj, obj);
    }
}

void curves_resolveAveragedSegments(GameObject* obj, CurvesCollisionState* collision) {
    f32 sum;
    MatrixTransform transform;
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

    collision->surfaceNormalX = collision->segmentHits.planes[0][0];
    collision->surfaceNormalY = collision->segmentHits.planes[0][1];
    collision->surfaceNormalZ = collision->segmentHits.planes[0][2];
    pointCount = collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT;
    if ((pointCount == 2) || (pointCount == 4)) {
        zero = 0.0f;
        obj->anim.worldPosX = zero;
        obj->anim.worldPosY = zero;
        obj->anim.worldPosZ = zero;

        pointIndex = 0;
        pointX = (f32*)collision;
        pointYZ = (f32*)collision;
        pointLimit = pointCount * 3;
        for (; pointIndex < pointLimit; pointIndex += 3) {
            obj->anim.worldPosX += pointX[2];
            obj->anim.worldPosY += pointYZ[3];
            obj->anim.worldPosZ += pointYZ[4];
            pointX += 3;
            pointYZ += 3;
        }

        scale = CURVES_ONE;
        averageScale = scale / pointCount;
        obj->anim.worldPosX *= averageScale;
        obj->anim.worldPosY *= averageScale;
        obj->anim.worldPosZ *= averageScale;

        if ((s32)(collision->flags & 0x8600) != 0) {
            transform.rotX = -obj->anim.rotX;
            transform.rotY = -obj->anim.rotY;
            transform.rotZ = -obj->anim.rotZ;
            transform.scale = scale;
            transform.x = -obj->anim.worldPosX;
            transform.y = -obj->anim.worldPosY;
            transform.z = -obj->anim.worldPosZ;
            mtxRotateByVec3s(matrix, &transform.rotX);

            i = 0;
            outZ = localZ;
            outY = localY;
            outX = localX;
            point = (f32*)collision;
            for (; i < pointCount; i++) {
                Matrix_TransformPoint(matrix, point[2], point[3], point[4], outX, outY, outZ);
                point += 3;
                outZ++;
                outY++;
                outX++;
            }

            idx1 = 1;
            idx2 = 2;
            idx3 = 3;
            if (pointCount == 2) {
                idx1 = 0;
                idx2 = 1;
                idx3 = 1;
            }
            if ((s32)(collision->flags & 0x8000) != 0) {
                sum = localX[0] + localX[idx1];
                secondArg = sum - (localX[idx2] + localX[idx3]);
                angle = (u16)getAngle(secondArg, (localZ[0] + localZ[idx1]) - (localZ[idx2] + localZ[idx3]));
                obj->anim.rotX += (s16)(u16)(angle + 0x8000) >> 2;
            }
            if ((s32)(collision->flags & 0x200) != 0) {
                f32 sumZ;
                sumZ = localZ[idx2] - localZ[idx1];
                sumZ += localZ[idx3] - localZ[0];
                sumZ *= CURVES_HALF;
                sum = localY[idx2] - localY[idx1];
                sum += localY[idx3] - localY[0];
                sum *= CURVES_HALF;
                angle = getAngle(sum, sumZ);
                collision->tiltPitch = -angle;
            }
            if ((pointCount == 4) && ((s32)(collision->flags & 0x400) != 0)) {
                f32 sumX;
                sumX = localX[idx1] - localX[0];
                sumX += localX[idx2] - localX[idx3];
                sumX *= CURVES_HALF;
                sum = localY[idx1] - localY[0];
                sum += localY[idx2] - localY[idx3];
                sum *= CURVES_HALF;
                angle = getAngle(sum, sumX);
                collision->tiltRoll = angle;
            }
        }
    } else {
        obj->anim.worldPosX = collision->points[0][0];
        obj->anim.worldPosY = collision->points[0][1];
        obj->anim.worldPosZ = collision->points[0][2];
    }
}

void curves_updateSurfaceTilt(GameObject* obj, int state) {
    CurvesCollisionState* collision;
    f32 normalZ;
    short pitch;
    int angle;
    f32 nx;
    f32 ny;
    f32 nz;
    short outVec[4];
    f32 matrixBuf[20];

    collision = (CurvesCollisionState*)state;
    if (((s8)collision->surfaceFlags & 0x10) != 0) {
        outVec[0] = -obj->anim.rotX;
        if (obj->anim.parent != NULL) {
            outVec[0] = outVec[0] - ((GameObject*)obj->anim.parent)->anim.rotX;
        }
        outVec[1] = 0;
        outVec[2] = 0;
        matrixBuf[0] = CURVES_ONE;
        matrixBuf[1] = 0.0f;
        matrixBuf[2] = 0.0f;
        matrixBuf[3] = 0.0f;
        mtxRotateByVec3s(&matrixBuf[4], outVec);
        Matrix_TransformPoint((f32*)((u8*)matrixBuf + 0x10), (double)collision->surfaceNormalX,
                              (double)collision->surfaceNormalY, (double)collision->surfaceNormalZ, &nx, &ny, &nz);
        angle = getAngle(ny, nz);
        pitch = 0x4000 - angle;
        collision->tiltPitchTarget = pitch;
        collision->tiltPitch =
            collision->tiltPitch + ((int)((u32)framesThisStep * ((int)pitch - collision->tiltPitch)) >> 3);
        angle = getAngle(ny, nx);
        pitch = -(0x4000 - angle);
        collision->tiltRollTarget = pitch;
        collision->tiltRoll =
            collision->tiltRoll + ((int)((u32)framesThisStep * ((int)pitch - collision->tiltRoll)) >> 3);
    } else {
        collision->tiltPitch = collision->tiltPitch - ((int)((int)collision->tiltPitch * framesThisStep) >> 3);
        collision->tiltRoll = collision->tiltRoll - ((int)((int)collision->tiltRoll * framesThisStep) >> 3);
        normalZ = 0.0f;
        collision->surfaceNormalX = 0.0f;
        collision->surfaceNormalY = CURVES_ONE;
        collision->surfaceNormalZ = normalZ;
    }
}

void curves_snapToNearestSurface(GameObject* obj, CurvesCollisionState* collision) {
    u32 hitCount;
    int hitIndex;
    f32 currentY;
    f32 window;
    TrackGroundHit* point;

    point = curves_getCurves(obj, collision->points[0][0], collision->points[0][2], &hitCount, 0);
    hitIndex = hitCount - 1;
    currentY = (obj)->anim.worldPosY;
    window = CURVES_DEFAULT_VERTICAL_WINDOW;
    while (hitIndex >= 0) {
        if ((s8)point[hitIndex].surfaceType != ROMCURVE_POINT_TYPE_WATER) {
            if ((currentY <= point[hitIndex].height) && (currentY >= (point[hitIndex].height - window))) {
                (obj)->anim.worldPosY = point[hitIndex].height;
                collision->surfaceNormalX = point[hitIndex].normalX;
                collision->surfaceNormalY = point[hitIndex].normalY;
                collision->surfaceNormalZ = point[hitIndex].normalZ;
                *(s8*)&collision->surfaceFlags |= 0x11;
                collision->surfaceCounter++;
            }
            window = CURVES_VERTICAL_TRACE_DISTANCE;
        }
        hitIndex--;
    }
}

void curves_resolveWaterFloorCeiling(GameObject* obj, CurvesCollisionState* collision) {
    int seg;
    int hitCount;
    TrackGroundHit* point;
    int i;
    s8 foundBelow;
    TrackGroundHit* points;
    f32 topSentinel;
    f32 one;
    f32 zero;
    f32 floorSentinel;

    seg = 0;
    topSentinel = CURVES_BOUNDS_MAX_SEED;
    floorSentinel = CURVES_BOUNDS_MIN_SEED;
    zero = 0.0f;
    one = CURVES_ONE;
    for (; seg < 1; seg++) {
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
        for (i = 0, point = points; i < hitCount; i++) {
            if ((s8)point->surfaceType != ROMCURVE_POINT_TYPE_WATER) {
                if ((foundBelow == 0) && (point->height < (CURVES_SURFACE_EPSILON + collision->points[0][1])) &&
                    (point->normalY > CURVES_SURFACE_NORMAL_Z_THRESHOLD)) {
                    collision->floorY[0] = point->height;
                    collision->floorGap[0] = collision->points[0][1] - point->height;
                    if ((s8)collision->segmentHits.surfaceTypes[0] == -1) {
                        *(u8*)&collision->segmentHits.surfaceTypes[0] = point->surfaceType;
                    }
                    foundBelow = 1;
                } else if ((point->height >= (CURVES_SURFACE_EPSILON + collision->points[0][1])) &&
                           (point->normalY < 0.0f)) {
                    collision->ceilingY[0] = point->height;
                }
            }
            point++;
        }
        if (foundBelow == 0) {
            collision->floorGap[0] = CURVES_NO_FLOOR_GAP;
        }
        if (((s8)collision->surfaceFlags & (0x10 << seg)) != 0) {
            collision->floorGap[0] = 0.0f;
        }
        point = points;
        for (i = 0; i < hitCount; i++) {
            if (((s8)point->surfaceType == ROMCURVE_POINT_TYPE_WATER) &&
                (point->normalY > CURVES_WATER_NORMAL_THRESHOLD) && (point->height < collision->ceilingY[0]) &&
                (point->height > collision->floorY[0])) {
                collision->waterY[0] = point->height;
                collision->waterNormalX[0] = point->normalX;
                collision->waterNormalY[0] = point->normalY;
                collision->waterNormalZ[0] = point->normalZ;
            }
            point++;
        }
        if (topSentinel != collision->waterY[0]) {
            collision->waterDepth[0] = collision->waterY[0] - collision->points[0][1];
        }
        collision->resultWaterY = collision->waterY[0];
        collision->resultFloorY = collision->floorY[0];
        collision->resultCeilingY = collision->ceilingY[0];
        collision->resultWaterDepth = collision->waterDepth[0];
        collision->resultFloorGap = collision->floorGap[0];
    }
}

void curves_updateLocalPointCollision(GameObject* obj, CurvesCollisionState* collision) {
    u8 pointCount;
    u32 flags;
    f32* localPoint;
    int zoff;
    int pointIndex;
    s32 pointLimit;
    int mode;
    f32 zero;
    f32 averageScale;
    f32 tempX;
    f32 tempZ;
    MatrixTransform transform;
    f32 matrix[16];

    pointCount = collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK;
    collision->localPointHitMask = zoff = 0;
    pointIndex = 0;
    while (pointIndex < pointCount) {
        if ((s32)(collision->flags & 0x200000) != 0) {
            mode = 2;
        } else {
            mode = 4;
        }
        collision->localPointHitMask |=
            trackGetLineIntersect(&collision->localPointTarget[0][zoff], &collision->localPointWorld[0][zoff],
                                  collision->localPointRadii[pointIndex], mode, &collision->localHit, obj,
                                  (u8)collision->primaryHitType, -1, 0, (s8)collision->activeTimer)
            << pointIndex;
        flags = collision->flags;
        if ((s32)(flags & 0x2000000) != 0) {
            if ((s32)(flags & 0x200000) != 0) {
                mode = 2;
            } else {
                mode = 4;
            }
            trackGetLineIntersect(&collision->localPointTarget[0][zoff], &collision->localPointWorld[0][zoff],
                                  collision->localPointRadii[pointIndex], mode, &collision->localHit, obj,
                                  (u8)collision->secondaryHitType, -1, 0, (s8)collision->activeTimer);
        }
        pointIndex++;
        zoff += 3;
    }
    if (pointCount > 1) {
        if ((s32)(collision->flags & CURVES_COLLISION_STATE_KEEP_POSITION) == 0) {
            zero = 0.0f;
            obj->anim.localPosX = zero;
            obj->anim.localPosZ = zero;
            pointIndex = 0;
            localPoint = (f32*)collision;
            pointLimit = pointCount * 3;
            for (; pointIndex < pointLimit; pointIndex += 3) {
                obj->anim.localPosX += localPoint[57];
                obj->anim.localPosZ += localPoint[59];
                localPoint += 3;
            }
            averageScale = CURVES_ONE / pointCount;
            obj->anim.localPosX *= averageScale;
            obj->anim.localPosZ *= averageScale;
        }
    } else if ((s32)(collision->flags & CURVES_COLLISION_STATE_KEEP_POSITION) == 0) {
        obj->anim.localPosX = collision->localPointWorld[0][0];
        obj->anim.localPosZ = collision->localPointWorld[0][2];
    }
    transform.rotX = obj->anim.rotX;
    if ((s32)(collision->flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
        transform.rotY = 0;
        transform.rotZ = 0;
    } else {
        transform.rotY = obj->anim.rotY;
        transform.rotZ = obj->anim.rotZ;
    }
    transform.scale = CURVES_ONE;
    transform.x = obj->anim.localPosX;
    transform.y = obj->anim.localPosY;
    transform.z = obj->anim.localPosZ;
    setMatrixFromObjectPos(matrix, &transform);
    for (zoff = 0; zoff < pointCount * 3; zoff += 3) {
        collision->localPointTarget[0][zoff] = collision->localPointWorld[0][zoff];
        collision->localPointTarget[0][zoff + 2] = collision->localPointWorld[0][zoff + 2];
        localPoint = collision->localPointPositions + zoff;
        Matrix_TransformPoint(matrix, localPoint[0], localPoint[1], localPoint[2], &tempX,
                              &collision->localPointTarget[0][zoff + 1], &tempZ);
    }
}

void curves_preparePointCollisionFrame(GameObject* obj, CurvesCollisionState* collision) {
    u32 flags;
    ObjHitboxTransformState* matrixSource;
    int iv[2];
    u8* wb[1];
    int off[1];
    int matrixOffset;
    f32* localPoint;
    f32 resetMin;
    f32 resetRange;
    f32 resetZero;
    MatrixTransform transform;
    f32 matrix[16];

    if ((s32)(collision->flags & CURVES_COLLISION_STATE_ACTIVE) != 0) {
        if ((void*)((GameObject*)obj)->anim.parent != NULL) {
            if ((((GameObject*)obj)->anim.parentAnim->hitboxTransformState != NULL) &&
                (ObjHits_IsObjectEnabled((ObjAnimComponent*)((GameObject*)obj)->anim.parent) != 0)) {
                matrixSource = ((GameObject*)obj)->anim.parentAnim->hitboxTransformState;
                matrixOffset = (matrixSource->activeMatrixIndex + 2) * 0x10;
                Matrix_TransformPoint((f32*)matrixSource + matrixOffset, ((GameObject*)obj)->anim.localPosX,
                                      ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                      &((GameObject*)obj)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosY,
                                      &((GameObject*)obj)->anim.worldPosZ);
            } else {
                Obj_TransformLocalPointToWorld(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                               ((GameObject*)obj)->anim.localPosZ, &((GameObject*)obj)->anim.worldPosX,
                                               &((GameObject*)obj)->anim.worldPosY, &((GameObject*)obj)->anim.worldPosZ,
                                               (GameObject*)((GameObject*)obj)->anim.parent);
            }
        } else {
            ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
        }
        flags = collision->flags;
        if ((s32)(flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) != 0) {
            transform.rotX = ((GameObject*)obj)->anim.rotX;
            if ((s32)(flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
                transform.rotY = 0;
                transform.rotZ = 0;
            } else {
                transform.rotY = ((GameObject*)obj)->anim.rotY;
                transform.rotZ = ((GameObject*)obj)->anim.rotZ;
            }
            transform.scale = CURVES_ONE;
            transform.x = ((GameObject*)obj)->anim.worldPosX;
            transform.y = ((GameObject*)obj)->anim.worldPosY;
            transform.z = ((GameObject*)obj)->anim.worldPosZ;
            setMatrixFromObjectPos(matrix, &transform);
            iv[0] = 0;
            iv[1] = iv[0];
            wb[0] = (u8*)collision;
            off[0] = iv[0];
            while (iv[1] < ((int)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT)) {
                localPoint = (f32*)((u8*)collision->segmentLocalPoints + off[0]);
                Matrix_TransformPoint(matrix, localPoint[0], localPoint[1], localPoint[2],
                                      ((CurvesCollisionState*)wb[0])->points[0], &collision->points[0][iv[0] + 1],
                                      &collision->points[0][iv[0] + 2]);
                collision->segmentHits.surfaceTypes[iv[1]] = -1;
                wb[0] += 0xc;
                off[0] += 0xc;
                iv[0] += 3;
                iv[1]++;
            }
            for (iv[1] = 0; iv[1] < ((int)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT); iv[1]++) {
                collision->traceStart[iv[1]][0] = collision->points[iv[1]][0];
                collision->traceStart[iv[1]][1] =
                    CURVES_TRACE_RADIUS_OFFSET + (collision->points[iv[1]][1] + collision->segmentHits.radii[iv[1]]);
                collision->traceStart[iv[1]][2] = collision->points[iv[1]][2];
            }
        }
        if (((GameObject*)obj)->anim.classId == 1) {
            collision->traceStart[2][0] = collision->points[2][0] = ((GameObject*)obj)->anim.worldPosX;
            collision->traceStart[2][1] = collision->points[2][1] =
                CURVES_FALLBACK_TRACE_HEIGHT + ((GameObject*)obj)->anim.worldPosY;
            collision->traceStart[2][2] = collision->points[2][2] = ((GameObject*)obj)->anim.worldPosZ;
        }
        collision->surfaceFlags = 0;
        collision->surfaceHitMask = 0;
        resetRange = CURVES_BOUNDS_MAX_SEED;
        collision->resultWaterY = resetRange;
        collision->resultFloorY = resetRange;
        resetMin = CURVES_BOUNDS_MIN_SEED;
        collision->resultCeilingY = resetMin;
        resetZero = 0.0f;
        collision->resultWaterDepth = resetZero;
        collision->resultFloorGap = resetZero;
        collision->contactObj = 0;
        for (iv[1] = 0; iv[1] < ((int)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT); iv[1]++) {
            collision->waterY[iv[1]] = resetRange;
            collision->floorY[iv[1]] = resetRange;
            collision->ceilingY[iv[1]] = resetMin;
        }
    }
}

void curves_updateLocalPointTransforms(GameObject* obj, CurvesCollisionState* collision) {
    u32 flags;
    u8* wb[1];
    int iv[2];
    int off[1];

    f32* localPoint;
    MatrixTransform transform;
    f32 matrix[16];

    flags = collision->flags;
    if (((s32)(flags & CURVES_COLLISION_STATE_ACTIVE) != 0) &&
        ((s32)(flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0)) {
        transform.rotX = ((GameObject*)obj)->anim.rotX;
        if ((s32)(flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
            transform.rotY = 0;
            transform.rotZ = 0;
        } else {
            transform.rotY = ((GameObject*)obj)->anim.rotY;
            transform.rotZ = ((GameObject*)obj)->anim.rotZ;
        }
        transform.scale = CURVES_ONE;
        transform.x = ((GameObject*)obj)->anim.localPosX;
        transform.y = ((GameObject*)obj)->anim.localPosY;
        transform.z = ((GameObject*)obj)->anim.localPosZ;
        setMatrixFromObjectPos(matrix, &transform);
        iv[0] = 0;
        iv[1] = iv[0];
        wb[0] = (u8*)collision;
        off[0] = iv[0];
        while (iv[1] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK)) {
            localPoint = (f32*)((u8*)collision->localPointPositions + off[0]);
            Matrix_TransformPoint(matrix, localPoint[0], localPoint[1], localPoint[2],
                                  ((CurvesCollisionState*)wb[0])->localPointWorld[0],
                                  &collision->localPointWorld[0][iv[0] + 1], &collision->localPointWorld[0][iv[0] + 2]);
            wb[0] += 0xc;
            off[0] += 0xc;
            iv[0] += 3;
            iv[1]++;
        }
        iv[0] = 0;
        for (; iv[0] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); iv[0]++) {
            collision->localPointTarget[iv[0]][0] = collision->localPointWorld[iv[0]][0];
            collision->localPointTarget[iv[0]][1] = CURVES_ONE + collision->localPointWorld[iv[0]][1];
            collision->localPointTarget[iv[0]][2] = collision->localPointWorld[iv[0]][2];
        }
        trackInvalidateDynamicSlotsForObject((GameObject*)obj);
    }
}

void curves_reset(GameObject* obj, CurvesCollisionState* collision) {
    u32 flags;
    u8* worldBase;
    int loopIdx[2];
    u8* wb[1];  /* worldBase walker (steps by 0xc) */
    int off[1]; /* byteOff walker (steps by 0xc) */
    f32* localPoint;
    f32 one;
    MatrixTransform transform;
    f32 matrix[16];

    curves_preparePointCollisionFrame(obj, collision);
    flags = collision->flags;
    if (((s32)(flags & CURVES_COLLISION_STATE_ACTIVE) != 0) &&
        ((s32)(flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0)) {
        transform.rotX = (obj)->anim.rotX;
        if ((s32)(flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
            transform.rotY = 0;
            transform.rotZ = 0;
        } else {
            transform.rotY = (obj)->anim.rotY;
            transform.rotZ = (obj)->anim.rotZ;
        }
        transform.scale = CURVES_ONE;
        transform.x = (obj)->anim.localPosX;
        transform.y = (obj)->anim.localPosY;
        transform.z = (obj)->anim.localPosZ;
        setMatrixFromObjectPos(matrix, &transform);
        loopIdx[0] = 0;
        loopIdx[1] = loopIdx[0];
        wb[0] = (u8*)collision;
        off[0] = loopIdx[0];
        while (loopIdx[1] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK)) {
            localPoint = (f32*)((u8*)collision->localPointPositions + off[0]);
            Matrix_TransformPoint(
                matrix, localPoint[0], localPoint[1], localPoint[2], ((CurvesCollisionState*)wb[0])->localPointWorld[0],
                &collision->localPointWorld[0][loopIdx[0] + 1], &collision->localPointWorld[0][loopIdx[0] + 2]);
            wb[0] += 0xc;
            off[0] += 0xc;
            loopIdx[0] += 3;
            loopIdx[1]++;
        }
        loopIdx[0] = 0;
        worldBase = (u8*)collision;
        one = CURVES_ONE;
        for (; loopIdx[0] < (collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); loopIdx[0]++) {
            ((CurvesCollisionState*)worldBase)->localPointTarget[0][0] =
                ((CurvesCollisionState*)worldBase)->localPointWorld[0][0];
            ((CurvesCollisionState*)worldBase)->localPointTarget[0][1] =
                one + ((CurvesCollisionState*)worldBase)->localPointWorld[0][1];
            ((CurvesCollisionState*)worldBase)->localPointTarget[0][2] =
                ((CurvesCollisionState*)worldBase)->localPointWorld[0][2];
            worldBase += 0xc;
        }
        trackInvalidateDynamicSlotsForObject(obj);
    }
}

f32 curves_sampleHeight(GameObject* obj, f32 x, f32 baseY, f32 z, f32 height) {
    int hitCount;
    f32 maxY;
    TrackGroundHit* point;
    int i;
    TrackGroundHit* points;

    points = curves_getCurves(obj, x, z, (u32*)&hitCount, 1);
    i = 0;
    point = points;
    maxY = baseY + height;
    for (; i < hitCount; i++) {
        if ((point->height < maxY) && (point->normalY > 0.0f)) {
            return points[i].height;
        }
        point++;
    }
    return baseY;
}

TrackGroundHit* curves_getCurves(GameObject* obj, f32 x, f32 z, u32* outCount, int queryAll) {
    int pairCount;
    TrackGroundHit** hitPoints;

    if (obj != sCurvesCachedHitObj) {
        sCurvesCachedHitObj = obj;
        sCurvesCachedHitCount = trackGetHeight(obj, x, obj->anim.worldPosY, z, &hitPoints, queryAll != 0 ? 1 : -2, 0);
        if (ROMCURVE_GETCURVES_MAX_POINTS < sCurvesCachedHitCount) {
            sCurvesCachedHitCount = ROMCURVE_GETCURVES_MAX_POINTS;
        }
        for (pairCount = 0; pairCount < sCurvesCachedHitCount; pairCount++) {
            sCurvesHitPoints[pairCount].height = hitPoints[pairCount]->height;
            sCurvesHitPoints[pairCount].normalX = hitPoints[pairCount]->normalX;
            sCurvesHitPoints[pairCount].normalY = hitPoints[pairCount]->normalY;
            sCurvesHitPoints[pairCount].normalZ = hitPoints[pairCount]->normalZ;
            sCurvesHitPoints[pairCount].object = hitPoints[pairCount]->object;
            sCurvesHitPoints[pairCount].surfaceType = hitPoints[pairCount]->surfaceType;
        }
    }
    *outCount = sCurvesCachedHitCount;
    return sCurvesHitPoints;
}

void curves_advanceCollision(GameObject* curveObj, CurvesCollisionState* state, f32 step) {
    int flags;
    CurvesCollisionState* collision;
    f32* sourcePoint;
    int parentMatrixOffset;
    /* Component offset and point index for transforming each packed point set. */
    int pointIndices[2];
    u8* outputCursor[1];
    u32 sourceOffset;
    ObjAnimComponent* linkedAnim;
    f32 invStep;
    f32 zero;
    f32 one;
    f32 m1a[16];
    f32 m1b[16];
    f32 m2b[16];
    f32 m2a[16];
    f32 mE[16];
    MatrixTransform s1a;
    MatrixTransform s1b;
    MatrixTransform s2b;
    MatrixTransform s2a;
    MatrixTransform sE;

    if ((s32)(state->flags & CURVES_COLLISION_STATE_ACTIVE) == 0) {
        return;
    }
    collision = state;
    one = CURVES_ONE;
    invStep = one / step;
    collision->contactObj = 0;
    if (collision->subtype == CURVES_COLLISION_SUBTYPE_OBJECT) {
        sCurvesCachedHitObj = 0;
        sCurvesCachedHitCount = 0;
        zero = 0.0f;
        collision->surfaceNormalX = zero;
        collision->surfaceNormalY = one;
        collision->surfaceNormalZ = zero;
        if (((s32)(state->flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0) &&
            ((collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK) != 0)) {
            s1a.rotX = curveObj->anim.rotX;
            if ((s32)(state->flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
                s1a.rotY = 0;
                s1a.rotZ = 0;
            } else {
                s1a.rotY = curveObj->anim.rotY;
                s1a.rotZ = curveObj->anim.rotZ;
            }
            s1a.scale = CURVES_ONE;
            s1a.x = curveObj->anim.localPosX;
            s1a.y = curveObj->anim.localPosY;
            s1a.z = curveObj->anim.localPosZ;
            setMatrixFromObjectPos(m1a, &s1a);
            pointIndices[0] = 0;
            pointIndices[1] = pointIndices[0];
            outputCursor[0] = (u8*)collision;
            sourceOffset = pointIndices[0];
            while (pointIndices[1] < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK)) {
                sourcePoint = (f32*)((u8*)collision->localPointPositions + sourceOffset);
                Matrix_TransformPoint(m1a, sourcePoint[0], sourcePoint[1], sourcePoint[2],
                                      (f32*)(outputCursor[0] + 228),
                                      &collision->localPointWorld[0][pointIndices[0] + 1],
                                      &collision->localPointWorld[0][pointIndices[0] + 2]);
                outputCursor[0] += 0xc;
                sourceOffset += 0xc;
                pointIndices[0] += 3;
                pointIndices[1]++;
            }
            curves_updateLocalPointCollision(curveObj, collision);
            if (curveObj->anim.parentAnim != NULL) {
                if ((curveObj->anim.parentAnim->hitboxTransformState != NULL) &&
                    (ObjHits_IsObjectEnabled(curveObj->anim.parentAnim) != 0)) {
                    parentMatrixOffset =
                        (curveObj->anim.parentAnim->hitboxTransformState->activeMatrixIndex + 2) * 0x10;
                    Matrix_TransformPoint(
                        &curveObj->anim.parentAnim->hitboxTransformState->matrices[0][0][0] + parentMatrixOffset,
                        curveObj->anim.localPosX, curveObj->anim.localPosY, curveObj->anim.localPosZ,
                        &curveObj->anim.worldPosX, &curveObj->anim.worldPosY, &curveObj->anim.worldPosZ);
                } else {
                    Obj_TransformLocalPointToWorld(curveObj->anim.localPosX, curveObj->anim.localPosY,
                                                   curveObj->anim.localPosZ, &curveObj->anim.worldPosX,
                                                   &curveObj->anim.worldPosY, &curveObj->anim.worldPosZ,
                                                   (GameObject*)curveObj->anim.parentAnim);
                }
            } else {
                curveObj->anim.worldPosX = curveObj->anim.localPosX;
                curveObj->anim.worldPosY = curveObj->anim.localPosY;
                curveObj->anim.worldPosZ = curveObj->anim.localPosZ;
            }
        }
        if (((s32)(state->flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) != 0) &&
            ((collision->pointCounts & CURVES_POINT_COUNT_SEGMENT_MASK) != 0)) {
            s1b.rotX = curveObj->anim.rotX;
            if ((s32)(state->flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
                s1b.rotY = 0;
                s1b.rotZ = 0;
            } else {
                s1b.rotY = curveObj->anim.rotY;
                s1b.rotZ = curveObj->anim.rotZ;
            }
            s1b.scale = CURVES_ONE;
            s1b.x = curveObj->anim.worldPosX;
            s1b.y = curveObj->anim.worldPosY;
            s1b.z = curveObj->anim.worldPosZ;
            setMatrixFromObjectPos(m1b, &s1b);
            pointIndices[0] = 0;
            pointIndices[1] = pointIndices[0];
            outputCursor[0] = (u8*)collision;
            sourceOffset = pointIndices[0];
            for (; pointIndices[1] < (int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT;
                 pointIndices[1]++) {
                sourcePoint = (f32*)((u8*)collision->segmentLocalPoints + sourceOffset);
                Matrix_TransformPoint(m1b, sourcePoint[0], sourcePoint[1], sourcePoint[2], (f32*)(outputCursor[0] + 8),
                                      &collision->points[0][pointIndices[0] + 1],
                                      &collision->points[0][pointIndices[0] + 2]);
                collision->segmentHits.surfaceTypes[pointIndices[1]] = -1;
                outputCursor[0] += 0xc;
                sourceOffset += 0xc;
                pointIndices[0] += 3;
            }
            if ((s32)(state->flags & 2) != 0) {
                *(char*)&collision->surfaceFlags =
                    trackGetIntersect(curveObj, (f32*)collision->traceStart, (f32*)collision->points,
                                      (int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT,
                                      collision->segmentHits.planes, 0);
                collision->surfaceCounter = collision->segmentHits.hitCount;
                collision->surfaceHitMask = 0;
            }
            switch (collision->updateMode) {
            case 1:
                curves_resolveSingleTrace(curveObj, collision);
                break;
            case 3:
                curves_countRandomPoints(curveObj, collision);
                break;
            case 4:
                collision->surfaceNormalX = collision->segmentHits.planes[0][0];
                collision->surfaceNormalY = collision->segmentHits.planes[0][1];
                collision->surfaceNormalZ = collision->segmentHits.planes[0][2];
                if ((((s8)collision->surfaceFlags & 1) != 0) && (collision->segmentHits.surfaceTypes[0] == 0x21)) {
                    curveObj->anim.worldPosX = collision->points[0][0];
                    curveObj->anim.worldPosY = collision->points[0][1];
                    curveObj->anim.worldPosZ = collision->points[0][2];
                }
                break;
            default:
                curves_resolveAveragedSegments(curveObj, collision);
                break;
            }
            if ((s32)(state->flags & 0x100) != 0) {
                curves_snapToNearestSurface(curveObj, collision);
            }
            if ((s32)(state->flags & 0x80) != 0) {
                curves_updateSurfaceTilt(curveObj, (int)state);
            }
            if ((s32)(state->flags & 1) != 0) {
                curves_resolveWaterFloorCeiling(curveObj, collision);
            }
            memcpy(collision->traceStart, collision->points,
                   ((int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT) * 0xc);
        }
        if ((s32)(state->flags & 0x800) != 0) {
            if (curveObj->anim.rotY > 0x3400) {
                curveObj->anim.rotY = 0x3400;
            }
            if (curveObj->anim.rotY < -0x3400) {
                curveObj->anim.rotY = -0x3400;
            }
        }
        if ((s32)(state->flags & 0x1000) != 0) {
            if (curveObj->anim.rotZ > 0x3400) {
                curveObj->anim.rotZ = 0x3400;
            }
            if (curveObj->anim.rotZ < -0x3400) {
                curveObj->anim.rotZ = -0x3400;
            }
        }
        if ((s32)(state->flags & 0x40000) == 0) {
            linkedAnim = curveObj->anim.linkedAnim;
            if ((linkedAnim != NULL) && ((*(s16*)&linkedAnim->eventTable & 1) != 0)) {
                curveObj->anim.velocityY = invStep * (curveObj->anim.worldPosY - linkedAnim->worldPosZ);
                if (curveObj->anim.worldPosY > curveObj->anim.linkedAnim->worldPosZ) {
                    curveObj->anim.velocityY = 0.0f;
                }
            } else {
                curveObj->anim.velocityY = invStep * (curveObj->anim.worldPosY - curveObj->anim.previousWorldPosY);
            }
        }
    } else if (collision->subtype == CURVES_COLLISION_SUBTYPE_POINT) {
        curves_preparePointCollisionFrame(curveObj, collision);
        flags = state->flags;
        if (((flags & CURVES_COLLISION_STATE_ACTIVE) != 0) && ((flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0)) {
            s2a.rotX = curveObj->anim.rotX;
            if ((flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
                s2a.rotY = 0;
                s2a.rotZ = 0;
            } else {
                s2a.rotY = curveObj->anim.rotY;
                s2a.rotZ = curveObj->anim.rotZ;
            }
            s2a.scale = CURVES_ONE;
            s2a.x = curveObj->anim.localPosX;
            s2a.y = curveObj->anim.localPosY;
            s2a.z = curveObj->anim.localPosZ;
            setMatrixFromObjectPos(m2a, &s2a);
            pointIndices[0] = 0;
            pointIndices[1] = pointIndices[0];
            outputCursor[0] = (u8*)collision;
            sourceOffset = pointIndices[0];
            while (pointIndices[1] < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK)) {
                sourcePoint = (f32*)((u8*)collision->localPointPositions + sourceOffset);
                Matrix_TransformPoint(m2a, sourcePoint[0], sourcePoint[1], sourcePoint[2],
                                      (f32*)(outputCursor[0] + 228),
                                      &collision->localPointWorld[0][pointIndices[0] + 1],
                                      &collision->localPointWorld[0][pointIndices[0] + 2]);
                outputCursor[0] += 0xc;
                sourceOffset += 0xc;
                pointIndices[0] += 3;
                pointIndices[1]++;
            }
            pointIndices[0] = 0;
            outputCursor[0] = (u8*)collision;
            one = CURVES_ONE;
            for (; pointIndices[0] < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); pointIndices[0]++) {
                *(f32*)(outputCursor[0] + 276) = *(f32*)(outputCursor[0] + 228);
                *(f32*)(outputCursor[0] + 280) = one + *(f32*)(outputCursor[0] + 232);
                *(f32*)(outputCursor[0] + 284) = *(f32*)(outputCursor[0] + 236);
                outputCursor[0] += 0xc;
            }
            trackInvalidateDynamicSlotsForObject(curveObj);
        }
        if ((s32)(state->flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) != 0) {
            s2b.rotX = curveObj->anim.rotX;
            if ((s32)(state->flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
                s2b.rotY = 0;
                s2b.rotZ = 0;
            } else {
                s2b.rotY = curveObj->anim.rotY;
                s2b.rotZ = curveObj->anim.rotZ;
            }
            s2b.scale = CURVES_ONE;
            s2b.x = curveObj->anim.worldPosX;
            s2b.y = curveObj->anim.worldPosY;
            s2b.z = curveObj->anim.worldPosZ;
            setMatrixFromObjectPos(m2b, &s2b);
            pointIndices[0] = 0;
            pointIndices[1] = pointIndices[0];
            outputCursor[0] = (u8*)collision;
            sourceOffset = pointIndices[0];
            for (; pointIndices[1] < (int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT;
                 pointIndices[1]++) {
                sourcePoint = (f32*)((u8*)collision->segmentLocalPoints + sourceOffset);
                Matrix_TransformPoint(m2b, sourcePoint[0], sourcePoint[1], sourcePoint[2], (f32*)(outputCursor[0] + 8),
                                      &collision->points[0][pointIndices[0] + 1],
                                      &collision->points[0][pointIndices[0] + 2]);
                collision->segmentHits.surfaceTypes[pointIndices[1]] = -1;
                outputCursor[0] += 0xc;
                sourceOffset += 0xc;
                pointIndices[0] += 3;
            }
            memcpy(collision->traceStart, collision->points,
                   ((int)(u32)collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT) * 0xc);
            if ((s32)(state->flags & 1) != 0) {
                curves_resolveWaterFloorCeiling(curveObj, collision);
            }
        }
    } else {
        curves_preparePointCollisionFrame(curveObj, collision);
        flags = state->flags;
        if (((flags & CURVES_COLLISION_STATE_ACTIVE) != 0) && ((flags & CURVES_COLLISION_STATE_LOCAL_POINTS) != 0)) {
            sE.rotX = curveObj->anim.rotX;
            if ((flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
                sE.rotY = 0;
                sE.rotZ = 0;
            } else {
                sE.rotY = curveObj->anim.rotY;
                sE.rotZ = curveObj->anim.rotZ;
            }
            sE.scale = CURVES_ONE;
            sE.x = curveObj->anim.localPosX;
            sE.y = curveObj->anim.localPosY;
            sE.z = curveObj->anim.localPosZ;
            setMatrixFromObjectPos(mE, &sE);
            pointIndices[0] = 0;
            pointIndices[1] = pointIndices[0];
            outputCursor[0] = (u8*)collision;
            sourceOffset = pointIndices[0];
            while (pointIndices[1] < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK)) {
                sourcePoint = (f32*)((u8*)collision->localPointPositions + sourceOffset);
                Matrix_TransformPoint(mE, sourcePoint[0], sourcePoint[1], sourcePoint[2], (f32*)(outputCursor[0] + 228),
                                      &collision->localPointWorld[0][pointIndices[0] + 1],
                                      &collision->localPointWorld[0][pointIndices[0] + 2]);
                outputCursor[0] += 0xc;
                sourceOffset += 0xc;
                pointIndices[0] += 3;
                pointIndices[1]++;
            }
            pointIndices[0] = 0;
            outputCursor[0] = (u8*)collision;
            one = CURVES_ONE;
            for (; pointIndices[0] < (int)(collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK); pointIndices[0]++) {
                *(f32*)(outputCursor[0] + 276) = *(f32*)(outputCursor[0] + 228);
                *(f32*)(outputCursor[0] + 280) = one + *(f32*)(outputCursor[0] + 232);
                *(f32*)(outputCursor[0] + 284) = *(f32*)(outputCursor[0] + 236);
                outputCursor[0] += 0xc;
            }
            trackInvalidateDynamicSlotsForObject(curveObj);
        }
    }
    if (curveObj->anim.parentAnim != NULL) {
        if ((curveObj->anim.parentAnim->hitboxTransformState != NULL) &&
            (ObjHits_IsObjectEnabled(curveObj->anim.parentAnim) != 0)) {
            parentMatrixOffset = (u32)curveObj->anim.parentAnim->hitboxTransformState->activeMatrixIndex * 0x10;
            Matrix_TransformPoint(&curveObj->anim.parentAnim->hitboxTransformState->matrices[0][0][0] +
                                      parentMatrixOffset,
                                  curveObj->anim.worldPosX, curveObj->anim.worldPosY, curveObj->anim.worldPosZ,
                                  &curveObj->anim.localPosX, &curveObj->anim.localPosY, &curveObj->anim.localPosZ);
        } else {
            Obj_TransformWorldPointToLocal(curveObj->anim.worldPosX, curveObj->anim.worldPosY, curveObj->anim.worldPosZ,
                                           &curveObj->anim.localPosX, &curveObj->anim.localPosY,
                                           &curveObj->anim.localPosZ, (GameObject*)curveObj->anim.parentAnim);
        }
    } else {
        curveObj->anim.localPosX = curveObj->anim.worldPosX;
        curveObj->anim.localPosY = curveObj->anim.worldPosY;
        curveObj->anim.localPosZ = curveObj->anim.worldPosZ;
    }
}

void curves_gatherTrackTriangles(GameObject* obj, CurvesCollisionState* state) {
    u32 flags;
    s8 type;
    u8 mask;
    mask = 0;
    flags = state->flags;
    if ((s32)(flags & CURVES_COLLISION_STATE_ACTIVE) == 0 || (s32)(flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) == 0) {
        return;
    }
    type = state->subtype;
    if (type == CURVES_COLLISION_SUBTYPE_OBJECT || type == CURVES_COLLISION_SUBTYPE_POINT) {
        if ((s32)(flags & 0x00000004) != 0) {
            mask |= 0x1;
        }
        if ((s32)(flags & 0x01000000) != 0) {
            mask |= 0x20;
        }
        trackIntersectBroadphase(obj, &state->hitBounds, mask, 1);
    }
}

void curves_updateQueryBounds(GameObject* obj, CurvesCollisionState* state, f32 step) {
    f32 maxX;
    f32 minX;
    f32 maxY;
    f32 minY;
    f32 maxZ;
    f32 minZ;
    f32 bound;
    f32* pin;
    f32* ptsWalk;
    int mtxIdx;
    int byteOff;
    int n;
    CurvesCollisionState* radSrc;
    CurvesCollisionState* traceSrc;
    f32 radiusScale;
    f32 rr;
    f32* radDst;
    f32* radWrite;
    f32* ptsRead;
    int i;
    int idx3;
    f32 m[16];
    f32 pts[12];
    MatrixTransform s;
    f32 radii[4];

    if (state->subtype == CURVES_COLLISION_SUBTYPE_NONE || (s32)(state->flags & CURVES_COLLISION_STATE_ACTIVE) == 0 ||
        (s32)(state->flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) == 0) {
        return;
    }
    {
        if ((void*)obj->anim.parent != NULL) {
            if ((obj->anim.parentAnim->hitboxTransformState != NULL) &&
                (ObjHits_IsObjectEnabled((ObjAnimComponent*)obj->anim.parent) != 0)) {
                mtxIdx = (obj->anim.parentAnim->hitboxTransformState->activeMatrixIndex + 2) * 0x10;
                Matrix_TransformPoint((f32*)obj->anim.parentAnim->hitboxTransformState + mtxIdx, obj->anim.localPosX,
                                      obj->anim.localPosY, obj->anim.localPosZ, &obj->anim.worldPosX,
                                      &obj->anim.worldPosY, &obj->anim.worldPosZ);
            } else {
                Obj_TransformLocalPointToWorld(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                               &obj->anim.worldPosX, &obj->anim.worldPosY, &obj->anim.worldPosZ,
                                               (GameObject*)obj->anim.parent);
            }
        } else {
            obj->anim.worldPosX = obj->anim.localPosX;
            obj->anim.worldPosY = obj->anim.localPosY;
            obj->anim.worldPosZ = obj->anim.localPosZ;
        }
        s.rotX = obj->anim.rotX;
        if ((s32)(state->flags & CURVES_COLLISION_STATE_X_ROTATION_ONLY) != 0) {
            s.rotY = 0;
            s.rotZ = 0;
        } else {
            s.rotY = obj->anim.rotY;
            s.rotZ = obj->anim.rotZ;
        }
        s.scale = CURVES_ONE;
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
        radiusScale = CURVES_RADIUS_SCALE;
        for (; i < (int)(u32)state->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT; i++) {
            pin = (f32*)((u8*)state->segmentLocalPoints + byteOff);
            Matrix_TransformPoint(m, pin[0], pin[1], pin[2], ptsWalk, pts + (idx3 + 1), pts + (idx3 + 2));
            *radDst = radSrc->segmentHits.radii[0];
            rr = radiusScale * *radDst;
            *radDst = sqrtf(rr * *radDst);
            ptsWalk = ptsWalk + 3;
            byteOff = byteOff + 0xc;
            idx3 = idx3 + 3;
            radSrc = (CurvesCollisionState*)((u8*)radSrc + 4);
            radDst = radDst + 1;
        }
        maxX = CURVES_BOUNDS_MAX_SEED;
        minX = CURVES_BOUNDS_MIN_SEED;
        maxY = maxX;
        minY = minX;
        maxZ = maxX;
        minZ = minX;
        traceSrc = state;
        for (n = 0; n < ((int)(u32)state->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT); n++) {
            bound = *ptsRead + *radWrite;
            if (bound > maxX) {
                maxX = bound;
            }
            bound = *ptsRead - *radWrite;
            if (bound < minX) {
                minX = bound;
            }
            bound = ptsRead[1] + *radWrite;
            if (bound > maxY) {
                maxY = bound;
            }
            bound = ptsRead[1] - *radWrite;
            if (bound < minY) {
                minY = bound;
            }
            bound = ptsRead[2] + *radWrite;
            if (bound > maxZ) {
                maxZ = bound;
            }
            bound = ptsRead[2] - *radWrite;
            if (bound < minZ) {
                minZ = bound;
            }
            bound = traceSrc->traceStart[0][0] + *radWrite;
            if (bound > maxX) {
                maxX = bound;
            }
            bound = traceSrc->traceStart[0][0] - *radWrite;
            if (bound < minX) {
                minX = bound;
            }
            bound = traceSrc->traceStart[0][1] + *radWrite;
            if (bound > maxY) {
                maxY = bound;
            }
            bound = traceSrc->traceStart[0][1] - *radWrite;
            if (bound < minY) {
                minY = bound;
            }
            bound = traceSrc->traceStart[0][2] + *radWrite;
            if (bound > maxZ) {
                maxZ = bound;
            }
            bound = traceSrc->traceStart[0][2] - *radWrite;
            if (bound < minZ) {
                minZ = bound;
            }
            ptsRead = ptsRead + 3;
            traceSrc = (CurvesCollisionState*)((u8*)traceSrc + 12);
            radWrite = radWrite + 1;
        }
        state->hitBounds.minX = minX;
        state->hitBounds.maxX = maxX;
        state->hitBounds.minY = (int)(minY - state->heightPadding);
        state->hitBounds.maxY = (int)(maxY + state->heightPadding);
        state->hitBounds.minZ = minZ;
        state->hitBounds.maxZ = maxZ;
    }
}
void curves_setSegmentCollision(CurvesCollisionState* state, int count, f32* segmentLocalPoints, f32* radii,
                                s8* types) {
    int i;

    state->pointCounts &= CURVES_POINT_COUNT_LOCAL_MASK;
    state->pointCounts |= (count & CURVES_POINT_COUNT_LOCAL_MASK) << CURVES_POINT_COUNT_SEGMENT_SHIFT;
    state->segmentLocalPoints = segmentLocalPoints;
    for (i = 0; i < count; i++) {
        state->segmentHits.queryTypes[i] = (s8)types[i];
        state->segmentHits.surfaceTypes[i] = -1;
        state->segmentHits.radii[i] = radii[i];
    }
    state->flags |= CURVES_COLLISION_STATE_HIT_SEGMENTS;
}

void curves_setLocalPointCollisionEx(CurvesCollisionState* state, int pointCount, f32* localPointPositions,
                                     f32* localPointRadii, int primaryHitType, int secondaryHitType) {
    state->pointCounts &= CURVES_POINT_COUNT_SEGMENT_MASK;
    state->pointCounts = (u8)(state->pointCounts | (pointCount & CURVES_POINT_COUNT_LOCAL_MASK));
    state->primaryHitType = primaryHitType;
    state->secondaryHitType = secondaryHitType;
    state->localPointPositions = localPointPositions;
    state->localPointRadii = localPointRadii;
    state->flags |= CURVES_COLLISION_STATE_SECONDARY_LOCAL_POINTS | CURVES_COLLISION_STATE_LOCAL_POINTS;
    state->activeTimer = 0xa;
}

void curves_setLocalPointCollision(CurvesCollisionState* state, int pointCount, f32* localPointPositions,
                                   f32* localPointRadii, int primaryHitType) {
    state->pointCounts &= CURVES_POINT_COUNT_SEGMENT_MASK;
    state->pointCounts = (u8)(state->pointCounts | (pointCount & CURVES_POINT_COUNT_LOCAL_MASK));
    state->primaryHitType = primaryHitType;
    state->localPointPositions = localPointPositions;
    state->localPointRadii = localPointRadii;
    state->flags |= CURVES_COLLISION_STATE_LOCAL_POINTS;
    state->activeTimer = 0xa;
}

void curves_clear(CurvesCollisionState* state, int updateMode, u32 flags, int subtype) {
    memset(state, 0, CURVES_COLLISION_STATE_SIZE);
    state->subtype = subtype;
    state->flags = flags | CURVES_COLLISION_STATE_ACTIVE;
    state->updateMode = updateMode;
    state->heightPadding = 5;
}

void dll_15_release_nop(void) {
}

void dll_15_initialise_nop(void) {
}

int playerHasKrazoaSpirit(u8 checkStoryBits, u32 bit) {
    if (checkStoryBits == 0) {
        return mainGetBit(bit);
    }
    if ((mainGetBit(GAMEBIT_ITEM_TestCombatSpirit_Got) != 0) || (mainGetBit(GAMEBIT_ITEM_SpiritTestFear_Got) != 0) ||
        (mainGetBit(GAMEBIT_K1_SPIRIT_COLLECTED) != 0) || (mainGetBit(GAMEBIT_ITEM_Spirit5_Got) != 0) ||
        (mainGetBit(GAMEBIT_ITEM_SpiritTestStrength_Got) != 0) || (mainGetBit(GAMEBIT_ITEM_Spirit6_Got) != 0)) {
        return 1;
    }
    return 0;
}

void saveFileStruct_setCheatActive(u8 optionIndex, u8 active) {
    SaveData* save;

    save = (SaveData*)saveData;
    if ((save->unlockedCheats & (1 << optionIndex)) == 0) {
        return;
    }
    if (active != 0) {
        save->enabledCheats |= 1 << optionIndex;
    } else {
        save->enabledCheats = save->enabledCheats & ~(1 << optionIndex);
    }
}

int saveFileStruct_isCheatActive(u8 idx) {
    SaveData* save;

    save = (SaveData*)saveData;
    if ((save->unlockedCheats & (1 << idx)) != 0) {
        if ((save->enabledCheats & (1 << idx)) != 0) {
            return 1;
        }
    }
    return 0;
}

void saveFileStruct_unlockCheat(u8 idx) {
    SaveData* p = (SaveData*)saveData;
    u32 reg = p->unlockedCheats;
    u32 mask = 1 << idx;
    p->unlockedCheats = reg | mask;
}

int isCheatUnlocked(u8 idx) {
    SaveData* p = (SaveData*)saveData;
    u32 reg = p->unlockedCheats;
    u32 mask = 1 << idx;
    return reg & mask;
}

void saveFileStruct_resetVolumes(void) {
    ((SaveData*)saveData)->musicVolume = 0x7f;
    ((SaveData*)saveData)->sfxVolume = 0x7f;
    ((SaveData*)saveData)->speechVolume = 0x7f;
}

SaveData* getSaveFileStruct(void) {
    return (SaveData*)saveData;
}

void loadSaveSettings(void) {
    setWidescreen(((SaveData*)saveData)->widescreenEnabled);
    setSubtitlesEnabled(((SaveData*)saveData)->subtitlesEnabled);
    setRumbleEnabled(((SaveData*)saveData)->rumbleEnabled);
    audioSetSoundMode(((SaveData*)saveData)->soundMode, 0);
    (*gGameUIInterface)->setUnusedHudSetting(((SaveData*)saveData)->gameUiSetting);
    (*gCameraInterface)->func1D(((SaveData*)saveData)->cameraSetting);
    audioSetVolumes(((SaveData*)saveData)->sfxVolume, 10, 0, 1, 0);
    audioSetVolumes(((SaveData*)saveData)->musicVolume, 10, 1, 0, 0);
    audioSetVolumes(((SaveData*)saveData)->speechVolume, 10, 0, 0, 1);
}

void* getLastSavedGameTexts(void) {
    return gSaveGameData + 0x558;
}

int pushable_savePos(GameObject* obj) {
    int i;
    SaveGameObjectPosition* position;
    u32 objectId;
    f32 savedX;

    for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++) {
        position = &((SaveGameObjectPosition*)gSaveGameData)[i];
        objectId = ((RomCurveDef*)obj->anim.placementData)->id;
        if (objectId == *(u32*)((u8*)&position->objectId + SAVEGAME_OBJECT_POSITION_OFFSET)) {
            if ((obj->anim.localPosX ==
                 (savedX = *(f32*)((int)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 4 + (i << 4)))) &&
                (obj->anim.localPosY == *(f32*)((int)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 8 + (i << 4))) &&
                (obj->anim.localPosZ ==
                 *(f32*)((int)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 0xc + (i << 4)))) {
                return 0;
            }
            obj->anim.localPosX = savedX;
            obj->anim.localPosY = *(f32*)((u32)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 8 + (i << 4));
            obj->anim.localPosZ = *(f32*)((u32)gSaveGameData + SAVEGAME_OBJECT_POSITION_OFFSET + 0xc + (i << 4));
            return 1;
        }
    }
    return 0;
}

const f32 lbl_803E06C4 = 0.0f;

typedef struct CurvesDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback clear;
    ObjectDescriptorCallback setLocalPointCollision;
    ObjectDescriptorCallback setSegmentCollision;
    ObjectDescriptorCallback updateQueryBounds;
    ObjectDescriptorCallback gatherTrackTriangles;
    ObjectDescriptorCallback advanceCollision;
    ObjectDescriptorCallback getCurves;
    ObjectDescriptorCallback reset;
    ObjectDescriptorCallback sampleHeight;
} CurvesDllInterface;

CurvesDllInterface dll_15_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)dll_15_initialise_nop,
    (ObjectDescriptorCallback)dll_15_release_nop,
    0,
    (ObjectDescriptorCallback)curves_clear,
    (ObjectDescriptorCallback)curves_setLocalPointCollision,
    (ObjectDescriptorCallback)curves_setSegmentCollision,
    (ObjectDescriptorCallback)curves_updateQueryBounds,
    (ObjectDescriptorCallback)curves_gatherTrackTriangles,
    (ObjectDescriptorCallback)curves_advanceCollision,
    (ObjectDescriptorCallback)curves_getCurves,
    (ObjectDescriptorCallback)curves_reset,
    (ObjectDescriptorCallback)curves_sampleHeight,
};
