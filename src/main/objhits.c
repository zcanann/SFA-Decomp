#include <string.h>
#include "main/game_object.h"
#include "main/model.h"
#include "main/objlib.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "main/dll/VF/vf_shared.h"

extern u8 hitDetectFn_80067958(int obj, float* startPoints, float* endPoints, int pointCount,
                                 void* outHits, int flags);
extern void hitDetectFn_800691c0(int obj, void* bounds, u32 mask, int flags);
extern void hitDetect_calcSweptSphereBounds(u32* boundsOut, float* startPoints, float* endPoints, float* radii,
                                            int pointCount);
extern void debugPrintf(char* fmt, ...);
extern f32 sqrtf(f32 v);
extern float mathCosf(float x);
extern ObjHitsSweepEntry* gObjHitsSweepEntryPtrs[OBJHITS_SWEEP_ENTRY_CAPACITY];
extern ObjHitsSweepEntry gObjHitsSweepEntries[OBJHITS_SWEEP_ENTRY_CAPACITY];
extern u8* gObjHitsPriorityHitStates;
extern f64 lbl_803DE928;
extern f32 oneOverTimeDelta;
extern f32 gObjHitsSweepSortSentinel;
extern f32 lbl_803DE91C;
extern f32 gObjHitsResponseClampMin;
extern f32 gObjHitsResponseClampMax;
extern f32 lbl_803DE920;
extern f32 lbl_803DE930;
extern f32 lbl_803DE934;
extern f32 lbl_803DE938;
extern f32 gObjHitsPi;
extern f32 gObjHitsAngleHalfPeriod;
extern f32 lbl_803DB450;

typedef struct ObjHitsVec3
{
    f32 x;
    f32 y;
    f32 z;
} ObjHitsVec3;

extern f32 gObjHitsPriorityHitTickDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

static inline ObjHitsModelBank* ObjHits_GetActiveModel(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (ObjHitsModelBank*)objAnim->banks[objAnim->bankIndex];
}

#pragma opt_propagation off
int ObjHits_CollectSkeletonHitsXZ(f32* point, f32 radius, ObjHitsSkeletonJointData* jointData,
                                  int* model, ObjHitsSkeletonHit* hits,
                                  ObjHitsSkeletonHit** outBest, f32 yMax, f32 yMin, f32* outAccum)
{
    float px2;
    float pz2;
    float diameter;
    float cullDist;
    int idx28;
    float* pRad;
    int idx4;
    float* radii;
    int joint;
    int parent;
    int count;
    ObjHitsModelFileHeader* modelFile;
    ObjHitsSkeletonHit* cur;
    ObjModelJointMatrix* jointMatrix;
    float dx;
    float dz;
    float radJ;
    float radP;
    float sumX;
    float sumZ;
    float dbl;
    float limit;
    float len2;
    float inv;
    float d;
    ObjHitsVec3 jointPos;
    ObjHitsVec3 parentPos;
    ObjHitsVec3 axisDir;
    float axial;
    float distSq;
    float radSum;

    count = 0;
    if (jointData == NULL)
    {
        return 0;
    }
    modelFile = *(ObjHitsModelFileHeader**)model;
    radii = jointData->jointRadii;
    diameter = radius + radius;
    cur = hits;
    *outBest = hits;
    *outAccum = gObjHitsScalarZero;
    jointMatrix = ObjModel_GetJointMatrix((u8*)model, 0);
    jointPos.x = jointMatrix->translationX;
    jointPos.y = jointMatrix->translationY;
    jointPos.z = jointMatrix->translationZ;
    dx = jointPos.x - point[0];
    dz = jointPos.z - point[2];
    cullDist = sqrtf(dx * dx + gObjHitsScalarZero + dz * dz) - radius;
    px2 = point[0] + point[0];
    pz2 = point[2] + point[2];
    joint = modelFile->jointCount;
    idx4 = joint * 4;
    idx28 = joint * 28;
    pRad = (float*)((u8*)radii + idx4);
    while (idx4 -= 4, idx28 -= 28, pRad -= 1, --joint != 0)
    {
        if (*(float*)((u8*)jointData->jointCullDistances + idx4) > cullDist)
        {
            parent = *(s8*)((u8*)modelFile->joints + idx28);
            jointMatrix = ObjModel_GetJointMatrix((u8*)model, joint);
            jointPos.x = jointMatrix->translationX;
            jointPos.y = jointMatrix->translationY;
            jointPos.z = jointMatrix->translationZ;
            jointMatrix = ObjModel_GetJointMatrix((u8*)model, parent);
            parentPos.x = jointMatrix->translationX;
            parentPos.y = jointMatrix->translationY;
            parentPos.z = jointMatrix->translationZ;
            jointData->touchedJoints[joint] = 1;
            jointData->touchedJoints[parent] = 1;
            radJ = *pRad;
            radP = radii[parent];
            if ((!(jointPos.y - radJ > yMax) || !(parentPos.y - radP > yMax)) &&
                (!(jointPos.y + radJ < yMin) || !(parentPos.y + radP < yMin)))
            {
                sumX = (parentPos.x + jointPos.x) - px2;
                sumZ = (parentPos.z + jointPos.z) - pz2;
                limit = *(float*)((u8*)jointData->jointLengths + idx4);
                if (radJ > radP)
                {
                    dbl = radJ + radJ;
                }
                else
                {
                    dbl = radP + radP;
                }
                limit = diameter + (limit + dbl);
                limit = limit * limit;
                if (sumX * sumX + gObjHitsScalarZero + sumZ * sumZ < limit)
                {
                    axisDir.x = parentPos.x - jointPos.x;
                    axisDir.y = parentPos.y - jointPos.y;
                    axisDir.z = parentPos.z - jointPos.z;
                    len2 = *(float*)((u8*)jointData->jointLengths + idx4);
                    if (len2 != gObjHitsScalarZero)
                    {
                        inv = gObjHitsScalarOne / len2;
                        axisDir.x = axisDir.x * inv;
                        axisDir.y = axisDir.y * inv;
                        axisDir.z = axisDir.z * inv;
                    }
                    jointData->touchedJoints[joint] = 0;
                    jointData->touchedJoints[parent] = 0;
                    if (ObjHits_TestTaperedCapsuleXZ(point, radius, radJ, radP, &jointPos.x, &axisDir.x,
                                                     &parentPos.x,
                                                     *(float*)((u8*)jointData->jointLengths + idx4),
                                                     &axial, &distSq, &radSum) != 0)
                    {
                        jointData->touchedJoints[joint] = 1;
                        jointData->touchedJoints[parent] = 1;
                        cur->signedSurfaceDistance = radius + (sqrtf(distSq) - radSum);
                        if (gObjHitsScalarZero == cur->signedSurfaceDistance)
                        {
                            cur->signedSurfaceDistance = lbl_803DE920;
                        }
                        d = (cur->signedSurfaceDistance > gObjHitsScalarZero)
                                ? cur->signedSurfaceDistance
                                : -cur->signedSurfaceDistance;
                        cur->inverseDistance = gObjHitsScalarOne / d;
                        *outAccum = *outAccum + cur->inverseDistance;
                        if (cur->signedSurfaceDistance < (*outBest)->signedSurfaceDistance)
                        {
                            *outBest = cur;
                        }
                        cur->pointARef = &jointPos.x;
                        cur->pointBRef = &parentPos.x;
                        cur->pointA[0] = jointPos.x;
                        cur->pointA[1] = jointPos.y;
                        cur->pointA[2] = jointPos.z;
                        cur->pointB[0] = parentPos.x;
                        cur->pointB[1] = parentPos.y;
                        cur->pointB[2] = parentPos.z;
                        cur->capsuleAxial = axial;
                        cur->radiusSum = radSum;
                        cur->centerDistance = sqrtf(distSq);
                        cur->axisDir[0] = axisDir.x;
                        cur->axisDir[1] = axisDir.y;
                        cur->axisDir[2] = axisDir.z;
                        cur->pointIndexA = joint;
                        cur->pointIndexB = parent;
                        if (count < OBJHITS_SKELETON_HIT_CAPACITY)
                        {
                            cur += 1;
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    cur->pointIndexA = OBJHITS_SKELETON_HIT_SENTINEL;
    return cur != hits;
}
int ObjHits_CollectSkeletonHits3D(f32* point, f32 radius, ObjHitsSkeletonJointData* jointData,
                                  int* model, ObjHitsSkeletonHit* hits,
                                  ObjHitsSkeletonHit** outBest, f32* outAccum)
{
    float px2;
    float pz2;
    float diameter;
    float cullDist;
    int idx28;
    float* pRad;
    int idx4;
    float* radii;
    int joint;
    int parent;
    int count;
    ObjHitsSkeletonHit* cur;
    ObjHitsModelFileHeader* modelFile;
    ObjModelJointMatrix* jointMatrix;
    float dx;
    float dz;
    float radJ;
    float radP;
    float sumX;
    float sumZ;
    float dbl;
    float limit;
    float inv;
    float d;
    ObjHitsVec3 jointPos;
    ObjHitsVec3 parentPos;
    ObjHitsVec3 axisDir;
    float axial;
    float distSq;
    float radSum;

    count = 0;
    if (jointData == NULL)
    {
        return 0;
    }
    modelFile = *(ObjHitsModelFileHeader**)model;
    radii = jointData->jointRadii;
    diameter = radius + radius;
    cur = hits;
    *outBest = hits;
    *outAccum = gObjHitsScalarZero;
    jointMatrix = ObjModel_GetJointMatrix((u8*)model, 0);
    jointPos.x = jointMatrix->translationX;
    jointPos.y = jointMatrix->translationY;
    jointPos.z = jointMatrix->translationZ;
    dx = jointPos.x - point[0];
    dz = jointPos.z - point[2];
    cullDist = sqrtf(dx * dx + gObjHitsScalarZero + dz * dz) - radius;
    px2 = point[0] + point[0];
    pz2 = point[2] + point[2];
    joint = modelFile->jointCount;
    idx4 = joint * 4;
    idx28 = joint * 28;
    pRad = (float*)((u8*)radii + idx4);
    while (idx4 -= 4, idx28 -= 28, pRad -= 1, --joint != 0)
    {
        if (*(float*)((u8*)jointData->jointCullDistances + idx4) > cullDist)
        {
            parent = *(s8*)((u8*)modelFile->joints + idx28);
            jointMatrix = ObjModel_GetJointMatrix((u8*)model, joint);
            jointPos.x = jointMatrix->translationX;
            jointPos.y = jointMatrix->translationY;
            jointPos.z = jointMatrix->translationZ;
            jointMatrix = ObjModel_GetJointMatrix((u8*)model, parent);
            parentPos.x = jointMatrix->translationX;
            parentPos.y = jointMatrix->translationY;
            parentPos.z = jointMatrix->translationZ;
            radJ = *pRad;
            radP = radii[parent];
            jointData->touchedJoints[joint] = 1;
            jointData->touchedJoints[parent] = 1;
            sumX = (parentPos.x + jointPos.x) - px2;
            sumZ = (parentPos.z + jointPos.z) - pz2;
            limit = *(float*)((u8*)jointData->jointLengths + idx4);
            if (radJ > radP)
            {
                dbl = radJ + radJ;
            }
            else
            {
                dbl = radP + radP;
            }
            limit = diameter + (limit + dbl);
            limit = limit * limit;
            if (sumX * sumX + gObjHitsScalarZero + sumZ * sumZ < limit)
            {
                axisDir.x = parentPos.x - jointPos.x;
                axisDir.y = parentPos.y - jointPos.y;
                axisDir.z = parentPos.z - jointPos.z;
                inv = gObjHitsScalarOne / *(float*)((u8*)jointData->jointLengths + idx4);
                axisDir.x = axisDir.x * inv;
                axisDir.y = axisDir.y * inv;
                axisDir.z = axisDir.z * inv;
                if (ObjHits_TestTaperedCapsule3D(point, radius, radJ, radP, &jointPos.x, &axisDir.x,
                                                 &parentPos.x,
                                                 *(float*)((u8*)jointData->jointLengths + idx4),
                                                 &axial, &distSq, &radSum) != 0)
                {
                    jointData->touchedJoints[joint] = 1;
                    jointData->touchedJoints[parent] = 1;
                    cur->signedSurfaceDistance = radius + (sqrtf(distSq) - radSum);
                    if (gObjHitsScalarZero == cur->signedSurfaceDistance)
                    {
                        cur->signedSurfaceDistance = lbl_803DE920;
                    }
                    d = (cur->signedSurfaceDistance > gObjHitsScalarZero)
                            ? cur->signedSurfaceDistance
                            : -cur->signedSurfaceDistance;
                    cur->inverseDistance = gObjHitsScalarOne / d;
                    *outAccum = *outAccum + cur->inverseDistance;
                    if (cur->signedSurfaceDistance < (*outBest)->signedSurfaceDistance)
                    {
                        *outBest = cur;
                    }
                    cur->pointARef = &jointPos.x;
                    cur->pointBRef = &parentPos.x;
                    cur->pointA[0] = jointPos.x;
                    cur->pointA[1] = jointPos.y;
                    cur->pointA[2] = jointPos.z;
                    cur->pointB[0] = parentPos.x;
                    cur->pointB[1] = parentPos.y;
                    cur->pointB[2] = parentPos.z;
                    cur->capsuleAxial = axial;
                    cur->radiusSum = radSum;
                    cur->centerDistance = sqrtf(distSq);
                    cur->axisDir[0] = axisDir.x;
                    cur->axisDir[1] = axisDir.y;
                    cur->axisDir[2] = axisDir.z;
                    cur->pointIndexA = joint;
                    cur->pointIndexB = parent;
                    if (count < OBJHITS_SKELETON_HIT_CAPACITY)
                    {
                        count += 1;
                        cur += 1;
                    }
                }
            }
        }
    }
    cur->pointIndexA = OBJHITS_SKELETON_HIT_SENTINEL;
    return cur != hits;
}
#pragma opt_propagation reset

int ObjHits_CalcSkeletonResponseXZ(f32* pos, f32 radius, int obj, ObjHitsSkeletonHit* hits,
                                   ObjHitsSkeletonJointData* jointPoints, int jointModel,
                                   ObjHitsSkeletonHit* bestHit, f32 t, f32 axial, f32* out)
{
    float moveLen;
    float zf;
    int idxA;
    float* pPtr;
    float* aPtr;
    ObjHitsSkeletonHit* saved;
    float* rPtr;
    float* norm;
    float* pb;
    float tdiff;
    struct
    {
        float out[9];
        ObjHitsVec3 accum;
    } pj;
    float reflect[3];
    float normalOut[3];
    ObjHitsVec3 normAccum;
    ObjHitsVec3 diff;
    ObjHitsVec3 move;
    ObjHitsVec3 projPos;

    aPtr = &pj.out[9];
    saved = hits;
    move.x = ((GameObject*)obj)->anim.worldPosX - ((GameObject*)obj)->anim.previousWorldPosX;
    move.y = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->anim.previousWorldPosY;
    move.z = ((GameObject*)obj)->anim.worldPosZ - ((GameObject*)obj)->anim.previousWorldPosZ;
    moveLen = Vec3_Length(&move.x);
    projPos.x = pos[0];
    projPos.y = pos[1];
    projPos.z = pos[2];
    move.x = move.x * t;
    move.y = move.y * t;
    move.z = move.z * t;
    projPos.x = projPos.x - move.x;
    projPos.y = projPos.y - move.y;
    projPos.z = projPos.z - move.z;
    pj.accum.x = gObjHitsScalarZero;
    pj.accum.y = gObjHitsScalarZero;
    pj.accum.z = gObjHitsScalarZero;
    normAccum.x = gObjHitsScalarZero;
    normAccum.y = gObjHitsScalarZero;
    normAccum.z = gObjHitsScalarZero;
    Vec3_Normalize(ObjHits_CalcTaperedCapsuleNormal(&projPos.x, bestHit->capsuleAxial,
                                                    bestHit->pointA, bestHit->pointB,
                                                    jointPoints->jointRadii[bestHit->pointIndexA],
                                                    jointPoints->jointRadii[bestHit->pointIndexB],
                                                    jointPoints->jointLengths[bestHit->pointIndexA], normalOut));
    pPtr = pj.out;
    zf = 0.0f;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1)
    {
        pb = ObjHits_ProjectPointToTaperedCapsuleXZ(&projPos.x, radius, hits->capsuleAxial,
                                                    hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
                                                    jointPoints->jointRadii[hits->pointIndexB],
                                                    jointPoints->jointLengths[idxA], pPtr);
        if (axial > zf)
        {
            hits->inverseDistance = hits->inverseDistance / axial;
        }
        else
        {
            hits->inverseDistance = zf;
        }
        pb[0] = pb[0] * hits->inverseDistance;
        pb[1] = pb[1] * hits->inverseDistance;
        pb[2] = pb[2] * hits->inverseDistance;
        pj.accum.x = pj.accum.x + pb[0];
        pj.accum.y = pj.accum.y + pb[1];
        pj.accum.z = pj.accum.z + pb[2];
        norm = ObjHits_CalcTaperedCapsuleNormal(pos, hits->capsuleAxial, hits->pointA,
                                                hits->pointB, jointPoints->jointRadii[hits->pointIndexA],
                                                jointPoints->jointRadii[hits->pointIndexB],
                                                jointPoints->jointLengths[hits->pointIndexA], normalOut);
        Vec3_Normalize(norm);
        normAccum.x = normAccum.x + norm[0];
        normAccum.y = normAccum.y + norm[1];
        normAccum.z = normAccum.z + norm[2];
    }
    Vec3_Normalize(&normAccum.x);
    diff.x = pj.accum.x - projPos.x;
    diff.y = gObjHitsScalarZero;
    diff.z = pj.accum.z - projPos.z;
    axial = Vec3_Length(&diff.x);
    diff.x = pj.accum.x - pos[0];
    diff.y = gObjHitsScalarZero;
    diff.z = pj.accum.z - pos[2];
    Vec3_Normalize(&move.x);
    if (moveLen > axial)
    {
        tdiff = gObjHitsScalarOne - t;
        t = lbl_803DE928 + tdiff * lbl_803DE930;
        move.x = move.x * (t * (moveLen - axial));
        move.y = move.y * (t * (moveLen - axial));
        move.z = move.z * (t * (moveLen - axial));
        Vec3_ReflectAgainstNormal(&normAccum.x, &move.x, rPtr = reflect);
    }
    else
    {
        rPtr = reflect;
        rPtr[0] = gObjHitsScalarZero;
        rPtr[1] = gObjHitsScalarZero;
        rPtr[2] = gObjHitsScalarZero;
    }
    pj.accum.x = pj.accum.x + rPtr[0];
    pj.accum.y = pj.accum.y + rPtr[1];
    pj.accum.z = pj.accum.z + rPtr[2];
    rPtr[0] = gObjHitsScalarZero;
    rPtr[1] = gObjHitsScalarZero;
    rPtr[2] = gObjHitsScalarZero;
    hits = saved;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1)
    {
        pb = ObjHits_ProjectPointToTaperedCapsuleXZ(aPtr, radius, hits->capsuleAxial,
                                                    hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
                                                    jointPoints->jointRadii[hits->pointIndexB],
                                                    jointPoints->jointLengths[idxA], pPtr);
        pb[0] = pb[0] * hits->inverseDistance;
        pb[1] = pb[1] * hits->inverseDistance;
        pb[2] = pb[2] * hits->inverseDistance;
        rPtr[0] = rPtr[0] + pb[0];
        rPtr[1] = rPtr[1] + pb[1];
        rPtr[2] = rPtr[2] + pb[2];
    }
    *out = rPtr[0] - pos[0];
    out[1] = gObjHitsScalarZero;
    out[2] = rPtr[2] - pos[2];
    return 1;
}

int ObjHits_CalcSkeletonResponse3D(f32* pos, f32 radius, int obj, ObjHitsSkeletonHit* hits,
                                   ObjHitsSkeletonJointData* jointPoints, int jointModel,
                                   ObjHitsSkeletonHit* bestHit, f32 t, f32 axial, f32* out)
{
    float moveLen;
    float zf;
    int idxA;
    float* pPtr;
    float* aPtr;
    ObjHitsSkeletonHit* saved;
    float* rPtr;
    float* norm;
    float* pb;
    struct
    {
        float out[9];
        ObjHitsVec3 accum;
    } pj;
    float reflect[3];
    float normalOut[3];
    ObjHitsVec3 normAccum;
    ObjHitsVec3 diff;
    ObjHitsVec3 move;
    ObjHitsVec3 projPos;

    aPtr = &pj.out[9];
    saved = hits;
    move.x = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX;
    move.y = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->anim.previousLocalPosY;
    move.z = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ;
    moveLen = Vec3_Length(&move.x);
    projPos.x = pos[0];
    projPos.y = pos[1];
    projPos.z = pos[2];
    projPos.x = projPos.x - move.x;
    projPos.y = projPos.y - move.y;
    projPos.z = projPos.z - move.z;
    pj.accum.x = gObjHitsScalarZero;
    pj.accum.y = gObjHitsScalarZero;
    pj.accum.z = gObjHitsScalarZero;
    normAccum.x = gObjHitsScalarZero;
    normAccum.y = gObjHitsScalarZero;
    normAccum.z = gObjHitsScalarZero;
    Vec3_Normalize(ObjHits_CalcTaperedCapsuleNormal(&projPos.x, bestHit->capsuleAxial,
                                                    bestHit->pointA, bestHit->pointB,
                                                    jointPoints->jointRadii[bestHit->pointIndexA],
                                                    jointPoints->jointRadii[bestHit->pointIndexB],
                                                    jointPoints->jointLengths[bestHit->pointIndexA], normalOut));
    pPtr = pj.out;
    zf = 0.0f;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1)
    {
        pb = ObjHits_ProjectPointToTaperedCapsule3D(&projPos.x, radius, hits->capsuleAxial,
                                                    hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
                                                    jointPoints->jointRadii[hits->pointIndexB],
                                                    jointPoints->jointLengths[idxA], pPtr);
        if (axial > zf)
        {
            hits->inverseDistance = hits->inverseDistance / axial;
        }
        else
        {
            hits->inverseDistance = zf;
        }
        pb[0] = pb[0] * hits->inverseDistance;
        pb[1] = pb[1] * hits->inverseDistance;
        pb[2] = pb[2] * hits->inverseDistance;
        pj.accum.x = pj.accum.x + pb[0];
        pj.accum.y = pj.accum.y + pb[1];
        pj.accum.z = pj.accum.z + pb[2];
        norm = ObjHits_CalcTaperedCapsuleNormal(pos, hits->capsuleAxial, hits->pointA,
                                                hits->pointB, jointPoints->jointRadii[hits->pointIndexA],
                                                jointPoints->jointRadii[hits->pointIndexB],
                                                jointPoints->jointLengths[hits->pointIndexA], normalOut);
        Vec3_Normalize(norm);
        normAccum.x = normAccum.x + norm[0];
        normAccum.y = normAccum.y + norm[1];
        normAccum.z = normAccum.z + norm[2];
    }
    Vec3_Normalize(&normAccum.x);
    diff.x = pj.accum.x - projPos.x;
    diff.y = pj.accum.y - projPos.y;
    diff.z = pj.accum.z - projPos.z;
    axial = Vec3_Length(&diff.x);
    diff.x = pj.accum.x - pos[0];
    diff.y = pj.accum.y - pos[1];
    diff.z = pj.accum.z - pos[2];
    Vec3_Normalize(&move.x);
    if (moveLen > axial)
    {
        move.x = move.x * (moveLen - axial);
        move.y = move.y * (moveLen - axial);
        move.z = move.z * (moveLen - axial);
        Vec3_ReflectAgainstNormal(&normAccum.x, &move.x, rPtr = reflect);
    }
    else
    {
        rPtr = reflect;
        rPtr[0] = gObjHitsScalarZero;
        rPtr[1] = gObjHitsScalarZero;
        rPtr[2] = gObjHitsScalarZero;
    }
    pj.accum.x = pj.accum.x + rPtr[0];
    pj.accum.y = pj.accum.y + rPtr[1];
    pj.accum.z = pj.accum.z + rPtr[2];
    rPtr[0] = gObjHitsScalarZero;
    rPtr[1] = gObjHitsScalarZero;
    rPtr[2] = gObjHitsScalarZero;
    hits = saved;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1)
    {
        pb = ObjHits_ProjectPointToTaperedCapsule3D(aPtr, radius, hits->capsuleAxial,
                                                    hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
                                                    jointPoints->jointRadii[hits->pointIndexB],
                                                    jointPoints->jointLengths[idxA], pPtr);
        pb[0] = pb[0] * hits->inverseDistance;
        pb[1] = pb[1] * hits->inverseDistance;
        pb[2] = pb[2] * hits->inverseDistance;
        rPtr[0] = rPtr[0] + pb[0];
        rPtr[1] = rPtr[1] + pb[1];
        rPtr[2] = rPtr[2] + pb[2];
    }
    *out = rPtr[0] - pos[0];
    out[1] = rPtr[1] - pos[1];
    out[2] = rPtr[2] - pos[2];
    return 1;
}

float* ObjHits_ProjectPointToTaperedCapsuleXZ(float* point, float pointRadius, float axial,
                                              float* base, float* tip, float baseRadius,
                                              float tipRadius, float length, float* out)
{
    float invLength;
    float zero;
    float axisDir[3];
    float surfacePoint[3];

    zero = gObjHitsScalarZero;
    if (axial < zero)
    {
        out[0] = point[0] - base[0];
        out[1] = zero;
        out[2] = point[2] - base[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + baseRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + base[0];
        out[1] = out[1] + base[1];
        out[2] = out[2] + base[2];
        return out;
    }
    if (axial > length)
    {
        out[0] = point[0] - tip[0];
        out[1] = zero;
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + tipRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + tip[0];
        out[1] = out[1] + tip[1];
        out[2] = out[2] + tip[2];
        return out;
    }
    axisDir[0] = tip[0] - base[0];
    axisDir[1] = tip[1] - base[1];
    axisDir[2] = tip[2] - base[2];
    invLength = gObjHitsScalarOne / length;
    axisDir[0] = axisDir[0] * invLength;
    axisDir[1] = axisDir[1] * invLength;
    axisDir[2] = axisDir[2] * invLength;
    Vec3_ScaleAdd(base, axisDir, axial, surfacePoint);
    out[0] = point[0] - surfacePoint[0];
    out[1] = gObjHitsScalarZero;
    out[2] = point[2] - surfacePoint[2];
    Vec3_Normalize(out);
    invLength = (tipRadius - baseRadius) * (axial / length);
    pointRadius = invLength + (baseRadius + pointRadius);
    out[0] = out[0] * pointRadius;
    out[1] = out[1] * pointRadius;
    out[2] = out[2] * pointRadius;
    out[0] = out[0] + surfacePoint[0];
    out[1] = out[1] + surfacePoint[1];
    out[2] = out[2] + surfacePoint[2];
    return out;
}

float* ObjHits_ProjectPointToTaperedCapsule3D(float* point, float pointRadius, float axial,
                                              float* base, float* tip, float baseRadius,
                                              float tipRadius, float length, float* out)
{
    float invLength;
    float axisDir[3];
    float surfacePoint[3];

    if (axial < gObjHitsScalarZero)
    {
        out[0] = point[0] - base[0];
        out[1] = point[1] - base[1];
        out[2] = point[2] - base[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + baseRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + base[0];
        out[1] = out[1] + base[1];
        out[2] = out[2] + base[2];
        return out;
    }
    if (axial > length)
    {
        out[0] = point[0] - tip[0];
        out[1] = point[1] - tip[1];
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + tipRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + tip[0];
        out[1] = out[1] + tip[1];
        out[2] = out[2] + tip[2];
        return out;
    }
    axisDir[0] = tip[0] - base[0];
    axisDir[1] = tip[1] - base[1];
    axisDir[2] = tip[2] - base[2];
    invLength = gObjHitsScalarOne / length;
    axisDir[0] = axisDir[0] * invLength;
    axisDir[1] = axisDir[1] * invLength;
    axisDir[2] = axisDir[2] * invLength;
    Vec3_ScaleAdd(base, axisDir, axial, surfacePoint);
    out[0] = point[0] - surfacePoint[0];
    out[1] = point[1] - surfacePoint[1];
    out[2] = point[2] - surfacePoint[2];
    Vec3_Normalize(out);
    invLength = (tipRadius - baseRadius) * (axial / length);
    pointRadius = invLength + (baseRadius + pointRadius);
    out[0] = out[0] * pointRadius;
    out[1] = out[1] * pointRadius;
    out[2] = out[2] * pointRadius;
    out[0] = out[0] + surfacePoint[0];
    out[1] = out[1] + surfacePoint[1];
    out[2] = out[2] + surfacePoint[2];
    return out;
}

float* ObjHits_CalcTaperedCapsuleNormal(float* point, float axial, float* base, float* tip,
                                        float baseRadius, float tipRadius, float length,
                                        float* out)
{
    float invAxial;
    float radiusDelta;
    float radiusOffset;
    float axisDir[3];
    float normal[3];
    float blended[3];
    float cross[3];
    float surface[3];

    if (axial <= gObjHitsScalarZero)
    {
        *out = *point - *tip;
        out[1] = point[1] - tip[1];
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        return out;
    }
    if (axial >= length)
    {
        *out = *point - *tip;
        out[1] = point[1] - tip[1];
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        return out;
    }
    else
    {
        radiusDelta = tipRadius - baseRadius;
        radiusOffset = radiusDelta * (axial / length);
        axisDir[0] = tip[0] - base[0];
        axisDir[1] = tip[1] - base[1];
        axisDir[2] = tip[2] - base[2];
        Vec3_Normalize(axisDir);
        Vec3_ScaleAdd(base, axisDir, axial, surface);
        normal[0] = point[0] - surface[0];
        normal[1] = point[1] - surface[1];
        normal[2] = point[2] - surface[2];
        Vec3_Normalize(normal);
        if (radiusDelta == gObjHitsScalarZero)
        {
            out[0] = normal[0];
            out[1] = normal[1];
            out[2] = normal[2];
            return out;
        }
        else
        {
            axisDir[0] = axisDir[0] * axial;
            axisDir[1] = axisDir[1] * axial;
            axisDir[2] = axisDir[2] * axial;
            Vec3_ScaleAdd(axisDir, normal, radiusOffset, blended);
            Vec3_Normalize(blended);
            axisDir[0] = axisDir[0] * (gObjHitsScalarOne / axial);
            invAxial = gObjHitsScalarOne / axial;
            axisDir[1] = axisDir[1] * invAxial;
            axisDir[2] = axisDir[2] * invAxial;
            Vec3_Cross(normal, axisDir, cross);
            Vec3_Normalize(cross);
            Vec3_Cross(cross, blended, out);
        }
    }
    return out;
}

int ObjHits_TestTaperedCapsuleXZ(float* point, float pointRadius, float baseRadius, float tipRadius,
                                 float* base, float* axis, float* tip, float length,
                                 float* axial, float* dist2, float* sumR)
{
    float deltaX, deltaZ;
    float radialX, radialZ;
    float tipDeltaX, tipDeltaZ;
    float projection;
    float radiusSum;

    deltaX = point[0] - base[0];
    deltaZ = point[2] - base[2];
    *axial = deltaX * axis[0] + deltaZ * axis[2];
    if (*axial > length)
    {
        tipDeltaX = (tip[0] - point[0]) * (tip[0] - point[0]);
        tipDeltaZ = (tip[2] - point[2]) * (tip[2] - point[2]);
        *dist2 = tipDeltaX + tipDeltaZ;
        radiusSum = pointRadius + tipRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    if (*axial < gObjHitsScalarZero)
    {
        *dist2 = deltaX * deltaX + deltaZ * deltaZ;
        radiusSum = pointRadius + baseRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    radialX = axis[0] * (projection = -*axial) + deltaX;
    radialZ = axis[2] * projection + deltaZ;
    *dist2 = radialX * radialX + radialZ * radialZ;
    radiusSum = (*axial / length) * (tipRadius - baseRadius) + (pointRadius + baseRadius);
    *sumR = radiusSum;
    return *dist2 <= radiusSum * radiusSum;
}

int ObjHits_TestTaperedCapsule3D(float* point, float pointRadius, float baseRadius, float tipRadius,
                                 float* base, float* axis, float* tip, float length,
                                 float* axial, float* dist2, float* sumR)
{
    float deltaX, deltaY, deltaZ;
    float radialX, radialY, radialZ;
    float tipDeltaX, tipDeltaY, tipDeltaZ;
    float radiusSum;

    deltaX = point[0] - base[0];
    deltaY = point[1] - base[1];
    deltaZ = point[2] - base[2];
    *axial = deltaZ * axis[2] + (deltaX * axis[0] + deltaY * axis[1]);
    if (*axial > length)
    {
        tipDeltaX = tip[0] - point[0];
        tipDeltaY = tip[1] - point[1];
        tipDeltaZ = tip[2] - point[2];
        *dist2 = tipDeltaZ * tipDeltaZ + (tipDeltaX * tipDeltaX + tipDeltaY * tipDeltaY);
        radiusSum = pointRadius + tipRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    if (*axial < gObjHitsScalarZero)
    {
        *dist2 = deltaZ * deltaZ + (deltaX * deltaX + deltaY * deltaY);
        radiusSum = pointRadius + baseRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    radialX = axis[0] * -*axial + deltaX;
    radialY = axis[1] * -*axial + deltaY;
    radialZ = axis[2] * -*axial + deltaZ;
    *dist2 = radialZ * radialZ + (radialX * radialX + radialY * radialY);
    radiusSum = (*axial / length) * (tipRadius - baseRadius) + (pointRadius + baseRadius);
    *sumR = radiusSum;
    return *dist2 <= radiusSum * radiusSum;
}

#pragma dont_inline on
void ObjHits_SortSweepEntries(ObjHitsSweepEntry** sweepPtrs, int entryCount)
{
    int gap;
    int maxGap;
    int index;
    int insertIndex;
    ObjHitsSweepEntry* prevEntry;
    ObjHitsSweepEntry* entry;

    gap = 1;
    maxGap = (entryCount - 1) / 9;
    for (; gap <= maxGap; gap = gap * 3 + 1)
    {
    }
    for (; gap > 0; gap = gap / 3)
    {
        for (index = gap + 1; index < entryCount; index++)
        {
            entry = sweepPtrs[index];
            insertIndex = index;
            while ((insertIndex > gap) &&
                (prevEntry = sweepPtrs[insertIndex - gap], prevEntry->minX > entry->minX))
            {
                sweepPtrs[insertIndex] = prevEntry;
                insertIndex -= gap;
            }
            sweepPtrs[insertIndex] = entry;
        }
    }
    return;
}
#pragma dont_inline reset

void ObjHits_TickPriorityHitCooldowns(void)
{
    int slotOffset;
    short slotIndex;
    u8* base;
    ObjHitsPriorityWorkSlot* workSlot;

    slotIndex = 0;
    slotOffset = 0;
    do
    {
        base = gObjHitsPriorityHitStates;
        workSlot = (ObjHitsPriorityWorkSlot*)(base + slotOffset);
        if (workSlot->active != 0)
        {
            workSlot->active--;
        }
        slotOffset = slotOffset + OBJHITS_PRIORITY_WORK_SLOT_SIZE;
        slotIndex++;
    }
    while (slotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT);
    gObjHitsPriorityHitTickDelta = timeDelta;
    return;
}

void ObjHitbox_UpdateRotatedBounds(ObjHitbox* hitbox, int advanceMatrix)
{
    typedef struct HitboxTransform
    {
        short x;
        short y;
        short z;
        float scale;
        float radiusX;
        float radiusY;
        float radiusZ;
    } HitboxTransform;
    ObjHitboxTransformState* transformState;
    int matrixBase;
    int matrixFloatOffset;
    HitboxTransform xform;

    transformState = hitbox->transformState;
    if (transformState != 0)
    {
        if (advanceMatrix != 0)
        {
            transformState->activeMatrixIndex = (transformState->activeMatrixIndex + 1) & 1;
        }
        matrixFloatOffset = transformState->activeMatrixIndex * OBJHITBOX_STATE_MATRIX_FLOAT_COUNT;
        matrixBase = (int)((float*)transformState->matrices + matrixFloatOffset);
        xform.x = -hitbox->rotationX;
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Y) != 0)
        {
            xform.y = 0;
        }
        else
        {
            xform.y = -hitbox->rotationY;
        }
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Z) != 0)
        {
            xform.z = 0;
        }
        else
        {
            xform.z = -hitbox->rotationZ;
        }
        xform.scale = gObjHitsScalarOne;
        xform.radiusX = -hitbox->radiusX;
        xform.radiusY = -hitbox->radiusY;
        xform.radiusZ = -hitbox->radiusZ;
        mtxRotateByVec3s((float*)matrixBase, &xform);
        xform.x = hitbox->rotationX;
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Y) != 0)
        {
            xform.y = 0;
        }
        else
        {
            xform.y = hitbox->rotationY;
        }
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Z) != 0)
        {
            xform.z = 0;
        }
        else
        {
            xform.z = hitbox->rotationZ;
        }
        xform.scale = gObjHitsScalarOne;
        xform.radiusX = hitbox->radiusX;
        xform.radiusY = hitbox->radiusY;
        xform.radiusZ = hitbox->radiusZ;
        matrixFloatOffset = (transformState->activeMatrixIndex + 2) * OBJHITBOX_STATE_MATRIX_FLOAT_COUNT;
        setMatrixFromObjectPos((float*)transformState->matrices + matrixFloatOffset, &xform);
        if (transformState->resetFrames != 0)
        {
            transformState->resetFrames--;
        }
    }
    return;
}

u8 ObjHits_CheckHitVolumes(int objA, int objB, int srcObj, char checkA, char checkB, u32 mask,
                           u32 volMask)
{
    int result;
    ObjHitsPriorityState* stateA;
    ObjHitsPriorityState* stateB;
    ObjHitsPriorityState* stateSrc;
    char modeA;
    char modeB;
    char miss;
    int countA;
    int countB;
    float* spheresA;
    float* spheresB;
    float* defA;
    ObjHitsModelHitVolume* volA;
    ObjHitsModelHitVolume* volB;
    float* curSphA;
    float* curDefA;
    float* contactBase;
    float* contact;
    float* cw;
    float* sphB;
    float* cr;
    ObjHitsModelHitVolume* p;
    float* pb2;
    ObjHitsModelBank* modelBank;
    ObjHitsModelFileHeader* modelFile;
    s64 maskA;
    s64 maskB;
    s64 volBits;
    s64 bitA;
    s64 bitB;
    int i;
    int j;
    int k;
    int count;
    int hit;
    int idxA;
    ObjHitsPriorityState* react;
    u32 linkA;
    u32 linkB;
    u16 link;
    float radiusA;
    float radiusB;
    float dxs;
    float dys;
    float dzs;
    float dsq;
    float radA2;
    float xA;
    float yA;
    float zA;
    float dax;
    float day;
    float daz;
    float sumSq;
    float ax;
    float ay;
    float az;
    float lenSq;
    float cx;
    float cy;
    float cz;
    float bb;
    float invLenSq;
    float minA;
    float maxA;
    float lo;
    float hi;
    float blo;
    float bhi;
    float cc;
    float sb0;
    float disc;
    float q;
    float sc;
    float bestDepth;
    float bestX;
    float bestZ;
    float defs[8];
    float sphs[8];
    u8 volB0[24];
    u8 volA0[24];

    result = 0;
    stateA = ObjAnim_GetPriorityHitState((ObjAnimComponent*)objA);
    stateB = ObjAnim_GetPriorityHitState((ObjAnimComponent*)objB);
    stateSrc = ObjAnim_GetPriorityHitState((ObjAnimComponent*)srcObj);
    if ((stateSrc->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) &&
        (*(s8*)&stateSrc->resetHitboxMode != 0 || stateSrc->activeHitboxMode != 0))
    {
        return 0;
    }
    if ((stateB->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) &&
        (*(s8*)&stateB->resetHitboxMode != 0 || stateB->activeHitboxMode != 0))
    {
        return 0;
    }
    modeA = 0;
    modeB = 0;
    if ((checkA != 0 && (stateA->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) != 0) ||
        (checkB != 0 && stateA->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES))
    {
        modelBank = ObjHits_GetActiveModel(objA);
        modelFile = modelBank->modelFile;
        countA = modelFile->hitVolumeCount;
        spheresA = modelBank->activeHitVolumeSpheres;
        defA = modelBank->hitVolumeSphereBuffers[((modelBank->hitBufferFlags >> 2) & 1) ^ 1];
        volA = modelFile->hitVolumes;
        if ((u32)srcObj != objA)
        {
            radiusA = stateSrc->secondaryRadiusXZ;
        }
        else
        {
            radiusA = stateA->secondaryRadiusXZ;
        }
        if ((((GameObject*)objA)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        {
            return 0;
        }
    }
    else
    {
        countA = 1;
        spheresA = sphs;
        defA = defs;
        volA = (ObjHitsModelHitVolume*)volA0;
        if (stateA->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE)
        {
            modeA = 1;
        }
        radiusA = stateA->secondaryRadius;
        sphs[0] = radiusA;
        sphs[1] = ((GameObject*)objA)->anim.worldPosX - playerMapOffsetX;
        sphs[2] = ((GameObject*)objA)->anim.worldPosY;
        sphs[3] = ((GameObject*)objA)->anim.worldPosZ - playerMapOffsetZ;
        defs[0] = radiusA;
        defs[1] = stateA->worldPosX - playerMapOffsetX;
        defs[2] = stateA->worldPosY;
        defs[3] = stateA->worldPosZ - playerMapOffsetZ;
        volA0[22] = 0;
        volA0[23] = 0;
        *(u16*)(volA0 + 20) = 0;
    }
    if ((checkA != 0 && (stateB->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) != 0) ||
        (checkB != 0 && stateB->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES))
    {
        modelBank = ObjHits_GetActiveModel(objB);
        modelFile = modelBank->modelFile;
        countB = modelFile->hitVolumeCount;
        spheresB = modelBank->activeHitVolumeSpheres;
        volB = modelFile->hitVolumes;
        radiusB = stateB->secondaryRadiusXZ;
        if ((((GameObject*)objB)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        {
            return 0;
        }
    }
    else
    {
        countB = 1;
        spheresB = &sphs[4];
        volB = (ObjHitsModelHitVolume*)volB0;
        if (stateB->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE)
        {
            modeB = 1;
        }
        radiusB = stateB->secondaryRadius;
        sphs[4] = radiusB;
        sphs[5] = ((GameObject*)objB)->anim.worldPosX - playerMapOffsetX;
        sphs[6] = ((GameObject*)objB)->anim.worldPosY;
        sphs[7] = ((GameObject*)objB)->anim.worldPosZ - playerMapOffsetZ;
        defs[4] = sphs[0];
        defs[5] = stateA->worldPosX - playerMapOffsetX;
        defs[6] = stateA->worldPosY;
        defs[7] = stateA->worldPosZ - playerMapOffsetZ;
        volB0[22] = 0;
        volB0[23] = 0;
        *(u16*)(volB0 + 20) = 0;
    }
    if (countA > 64 || countB > 64)
    {
        debugPrintf(sObjHitsTooManyHitSpheresWarning);
    }
    dxs = ((GameObject*)objA)->anim.worldPosX - ((GameObject*)objB)->anim.worldPosX;
    dys = ((GameObject*)objA)->anim.worldPosY - ((GameObject*)objB)->anim.worldPosY;
    dzs = ((GameObject*)objA)->anim.worldPosZ - ((GameObject*)objB)->anim.worldPosZ;
    dsq = sqrtf(dzs * dzs + (dxs * dxs + (dys * dys)));
    if (dsq > lbl_803DE934 + (radiusA + radiusB))
    {
        return 0;
    }
    maskA = 0;
    maskB = 0;
    volBits = 0;
    i = 0;
    p = volA;
    for (; i < countA; i++)
    {
        if (i == p->sphereIndex)
        {
            if ((mask & 1 << p->maskBit) != 0)
            {
                maskA |= 1 << i;
            }
            if ((volMask & 1 << p->maskBit) != 0)
            {
                volBits |= 1 << i;
            }
        }
        p++;
    }
    j = 0;
    p = volB;
    for (; j < countB; j++)
    {
        if (j == p->sphereIndex)
        {
            maskB |= 1 << j;
        }
        p++;
    }
    contactBase = gObjHitsContactScratch;
    bestDepth = lbl_803DE938;
    count = 1;
    while (count != 0)
    {
        count = 0;
        i = 0;
        curSphA = spheresA;
        curDefA = defA;
        contact = contactBase;
        for (; i < countA; i++)
        {
            bitA = 1 << i;
            if ((maskA & bitA) != 0)
            {
                radA2 = curSphA[0];
                xA = curSphA[1];
                yA = curSphA[2];
                zA = curSphA[3];
                miss = 1;
                if ((volBits & bitA) != 0)
                {
                    miss = 0;
                }
                if (miss == 0)
                {
                    dax = curDefA[1];
                    day = curDefA[2];
                    daz = curDefA[3];
                    ax = xA - dax;
                    ay = yA - day;
                    az = zA - daz;
                    lenSq = az * az + (ax * ax + (ay * ay));
                    if (lenSq > gObjHitsScalarZero)
                    {
                        invLenSq = gObjHitsScalarOne / lenSq;
                    }
                    else
                    {
                        miss = 1;
                    }
                }
                j = 0;
                sphB = spheresB;
                cw = contact;
                minA = yA - radA2;
                maxA = yA + radA2;
                for (; j < countB; j++)
                {
                    bitB = 1 << j;
                    if ((maskB & bitB) != 0)
                    {
                        hit = 0;
                        if ((i == 0 && modeA != 0) || (j == 0 && modeB != 0))
                        {
                            if (modeA != 0)
                            {
                                lo = yA + stateA->secondaryCapsuleOffsetA;
                                hi = yA + stateA->secondaryCapsuleOffsetB;
                                blo = sphB[2] - sphB[0];
                                bhi = sphB[2] + sphB[0];
                            }
                            else
                            {
                                lo = minA;
                                hi = maxA;
                                blo = stateB->secondaryCapsuleOffsetA + sphB[2];
                                bhi = stateB->secondaryCapsuleOffsetB + sphB[2];
                            }
                            if ((!(blo < lo) || !(bhi < lo)) && (!(blo > hi) || !(bhi > hi)))
                            {
                                sumSq = radA2 + sphB[0];
                                sumSq = sumSq * sumSq;
                                dxs = xA - sphB[1];
                                dsq = dxs * dxs;
                                if (dsq < sumSq)
                                {
                                    dzs = zA - sphB[3];
                                    dsq = dzs * dzs + dsq;
                                    if (dsq < sumSq)
                                    {
                                        dys = gObjHitsScalarZero;
                                        hit = 1;
                                    }
                                }
                            }
                        }
                        else
                        {
                            sumSq = (radA2 + sphB[0]) * (radA2 + sphB[0]);
                            if (miss != 0)
                            {
                                dxs = xA - sphB[1];
                                dsq = dxs * dxs;
                                if (dsq < sumSq)
                                {
                                    dys = yA - sphB[2];
                                    dsq = dys * dys + dsq;
                                    if (dsq < sumSq)
                                    {
                                        dzs = zA - sphB[3];
                                        dsq = dzs * dzs + dsq;
                                        if (dsq < sumSq)
                                        {
                                            hit = 1;
                                        }
                                    }
                                }
                            }
                            else
                            {
                                cx = dax - sphB[1];
                                cy = day - sphB[2];
                                cz = daz - sphB[3];
                                cc = (cz * cz + (cx * cx + (cy * cy))) - sumSq;
                                bb = cz * az + (cx * ax + (cy * ay));
                                if (!(bb > gObjHitsScalarZero) || !(cc > gObjHitsScalarZero))
                                {
                                    disc = bb * bb - lenSq * cc;
                                    if (disc >= gObjHitsScalarZero)
                                    {
                                        q = lenSq + bb;
                                        if (q >= gObjHitsScalarZero || q * q <= disc)
                                        {
                                            hit = 1;
                                            sc = sqrtf(disc);
                                            sc = invLenSq * -(bb + sc);
                                            dxs = ax * sc + cx;
                                            dys = ay * sc + cy;
                                            dzs = az * sc + cz;
                                            dsq = dzs * dzs + (dxs * dxs + (dys * dys));
                                        }
                                    }
                                }
                            }
                        }
                        if (hit != 0 && count < 64)
                        {
                            if (checkB != 0)
                            {
                                if (dsq > gObjHitsScalarZero)
                                {
                                    bb = sqrtf(sumSq);
                                    dsq = sqrtf(dsq);
                                    if (bb > gObjHitsScalarZero)
                                    {
                                        sumSq = (bb - dsq) / bb;
                                    }
                                    else
                                    {
                                        sumSq = gObjHitsScalarZero;
                                    }
                                    cw[5] = sumSq;
                                    cw[0] = dxs * sumSq;
                                    cw[1] = dzs * sumSq;
                                }
                            }
                            else
                            {
                                sumSq = sqrtf(dzs * dzs + (dxs * dxs + (dys * dys)));
                                if (sumSq > gObjHitsScalarZero)
                                {
                                    dxs = dxs / sumSq;
                                    dys = dys / sumSq;
                                    dzs = dzs / sumSq;
                                }
                                sb0 = sphB[0];
                                cw[2] = dxs * sb0;
                                cw[3] = dys * sb0;
                                cw[4] = dzs * sb0;
                            }
                            *((u8*)cw + 24) = i;
                            *((u8*)cw + 25) = j;
                            cw += 7;
                            contact += 7;
                            count += 1;
                        }
                    }
                    sphB += 4;
                }
            }
            curSphA += 4;
            curDefA += 4;
        }
        maskA = 0;
        maskB = 0;
        k = 0;
        cr = contactBase;
        for (; k < count; k++)
        {
            idxA = *((u8*)cr + 24);
            hit = *((u8*)cr + 25);
            linkA = volA[idxA].linkedSpheres;
            linkB = volB[hit].linkedSpheres;
            link = linkA;
            while (link != 0)
            {
                maskA |= 1 << (idxA + (u16)((link & 0xf000) >> 12));
                link = link << 4;
            }
            link = linkB;
            while (link != 0)
            {
                maskB |= 1 << (hit + (u16)((link & 0xf000) >> 12));
                link = link << 4;
            }
            if (linkA == 0 && linkB == 0)
            {
                if (checkA != 0)
                {
                    pb2 = &spheresB[hit * 4];
                    ((int (*)(f32, int, int, u8, u8, char, f32, f32))ObjHits_RecordPositionHit)(
                        pb2[1] + cr[2], objB, objA, stateSrc->hitVolumePriority, stateSrc->hitVolumeId,
                        hit, (modeB != 0) ? spheresA[idxA * 4 + 2] : pb2[2] + cr[3], pb2[3] + cr[4]);
                    result = 1;
                }
                else if (checkB != 0)
                {
                    if (cr[5] > bestDepth)
                    {
                        bestDepth = cr[5];
                        bestX = cr[0];
                        bestZ = cr[1];
                    }
                }
            }
            else if (linkA == 0)
            {
                maskA |= 1 << idxA;
            }
            else if (linkB == 0)
            {
                maskB |= 1 << hit;
            }
            cr += 7;
        }
    }
    if (checkA != 0 && result != 0)
    {
        if ((stateA->flags & 0x80) != 0)
        {
            react = ObjAnim_GetPriorityHitState((ObjAnimComponent*)objA);
            if (react != 0)
            {
                react->flags = react->flags & ~OBJHITS_PRIORITY_STATE_ENABLED;
            }
        }
        if ((stateB->flags & 0x80) != 0)
        {
            react = ObjAnim_GetPriorityHitState((ObjAnimComponent*)objB);
            if (react != 0)
            {
                react->flags = react->flags & ~OBJHITS_PRIORITY_STATE_ENABLED;
            }
        }
        return 1;
    }
    if (checkB != 0)
    {
        if (bestDepth > gObjHitsScalarZero)
        {
            if ((u32)objA == srcObj)
            {
                extern int ObjHits_RecordObjectHit(int obj, int hitObj, u8 priority, u8 hitVolume,
                                                   s8 sphereIndex);
                ObjHits_RecordObjectHit(objB, objA, stateSrc->objectPairPriority, stateSrc->objectPairHitVolume,
                                        hit);
                ObjHits_RecordObjectHit(objA, objB, stateB->objectPairPriority, stateB->objectPairHitVolume,
                                        idxA);
                ObjHits_ApplyPairResponse(objA, objB, -bestX, gObjHitsScalarZero, -bestZ, 0);
                return 1;
            }
        }
    }
    return 0;
}

#pragma dont_inline on
void doNothing_800333C8(int objA, int objB, int att, void* state, void* attState, f32 dt)
{
}
#pragma dont_inline reset

void ObjHits_CheckObjectHitVolumes(int objA, int objB, int attA, int attB, f32 dt)
{
    ObjHitsPriorityState* stateA;
    ObjHitsPriorityState* stateB;
    ObjHitsPriorityState* attStateA;
    ObjHitsPriorityState* attStateB;
    ObjHitsModelBank* hitboxBuf;
    u32 bufIndex;
    u32 mask;
    u8 result;
    extern int ObjHits_CheckHitVolumes(int objA, int objB, int srcObj, char checkA, char checkB,
                                       u32 mask, int skelMask);

    stateB = (ObjHitsPriorityState*)((GameObject*)objB)->anim.hitReactState;
    stateA = (ObjHitsPriorityState*)((GameObject*)objA)->anim.hitReactState;
    if ((u32)attA != 0)
    {
        attStateA = ObjAnim_GetPriorityHitState((ObjAnimComponent*)attA);
    }
    else
    {
        attStateA = NULL;
    }
    if ((u32)attB != 0)
    {
        attStateB = ObjAnim_GetPriorityHitState((ObjAnimComponent*)attB);
    }
    else
    {
        attStateB = NULL;
    }
    result = 0;
    if ((stateA->objectHitMask != 0) && ((s8)stateA->suppressOutgoingHits == 0))
    {
        if (((GameObject*)objA)->anim.classId == 1)
        {
            hitboxBuf = ObjHits_GetActiveModel(objA);
            bufIndex = (hitboxBuf->hitBufferFlags >> 2) & 1;
            if ((stateA->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0)
            {
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsPrimaryHitboxBufferScratch0,
                       hitboxBuf->modelFile->hitVolumeCount << 4);
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1], gObjHitsPrimaryHitboxBufferScratch1,
                       hitboxBuf->modelFile->hitVolumeCount << 4);
            }
            else
            {
                memcpy(gObjHitsPrimaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                       hitboxBuf->modelFile->hitVolumeCount << 4);
                memcpy(gObjHitsPrimaryHitboxBufferScratch1, hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                       hitboxBuf->modelFile->hitVolumeCount << 4);
            }
            if ((u32)attA != 0)
            {
                hitboxBuf = ObjHits_GetActiveModel(attA);
                bufIndex = (hitboxBuf->hitBufferFlags >> 2) & 1;
                if ((stateA->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0)
                {
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsSecondaryHitboxBufferScratch0,
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                           gObjHitsSecondaryHitboxBufferScratch1,
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                }
                else
                {
                    memcpy(gObjHitsSecondaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                    memcpy(gObjHitsSecondaryHitboxBufferScratch1,
                           hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                    stateA->flags = stateA->flags | OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED;
                }
            }
        }
        mask = stateA->objectHitMask >> 4;
        if (mask != 0)
        {
            result = ObjHits_CheckHitVolumes(objA, objB, objA, 1, 0, mask, stateA->skeletonHitMask >> 4);
        }
        if ((((u32)attA != 0) && (result == 0)) &&
            (mask = stateA->objectHitMask & 0xf, mask != 0))
        {
            result = ObjHits_CheckHitVolumes(attA, objB, objA, 1, 0, mask, stateA->skeletonHitMask & 0xf);
        }
        if ((result == 0) && (((GameObject*)objA)->anim.classId == 1))
        {
            doNothing_800333C8(objA, objB, attA, stateA, attStateA, dt);
        }
    }
    result = 0;
    if (((stateB->sourceMask & 0x80) == 0) && (stateB->objectHitMask != 0) &&
        ((s8)stateB->suppressOutgoingHits == 0))
    {
        if (((GameObject*)objB)->anim.classId == 1)
        {
            hitboxBuf = ObjHits_GetActiveModel(objB);
            bufIndex = (hitboxBuf->hitBufferFlags >> 2) & 1;
            if ((stateB->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0)
            {
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsPrimaryHitboxBufferScratch0,
                       hitboxBuf->modelFile->hitVolumeCount << 4);
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1], gObjHitsPrimaryHitboxBufferScratch1,
                       hitboxBuf->modelFile->hitVolumeCount << 4);
            }
            else
            {
                memcpy(gObjHitsPrimaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                       hitboxBuf->modelFile->hitVolumeCount << 4);
                memcpy(gObjHitsPrimaryHitboxBufferScratch1, hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                       hitboxBuf->modelFile->hitVolumeCount << 4);
            }
            if ((u32)attB != 0)
            {
                hitboxBuf = ObjHits_GetActiveModel(attB);
                bufIndex = (hitboxBuf->hitBufferFlags >> 2) & 1;
                if ((stateB->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0)
                {
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsSecondaryHitboxBufferScratch0,
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                           gObjHitsSecondaryHitboxBufferScratch1,
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                }
                else
                {
                    memcpy(gObjHitsSecondaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                    memcpy(gObjHitsSecondaryHitboxBufferScratch1,
                           hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                           hitboxBuf->modelFile->hitVolumeCount << 4);
                    stateB->flags = stateB->flags | OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED;
                }
            }
        }
        mask = stateB->objectHitMask >> 4;
        if (mask != 0)
        {
            result = ObjHits_CheckHitVolumes(objB, objA, objB, 1, 0, mask, stateB->skeletonHitMask >> 4);
        }
        if ((((u32)attB != 0) && (result == 0)) &&
            (mask = stateB->objectHitMask & 0xf, mask != 0))
        {
            result = ObjHits_CheckHitVolumes(attB, objA, objB, 1, 0, mask, stateB->skeletonHitMask & 0xf);
        }
        if ((result == 0) && (((GameObject*)objB)->anim.classId == 1))
        {
            doNothing_800333C8(objB, objA, attB, stateB, attStateB, dt);
        }
    }
}

void ObjHits_RegisterActiveHitVolumeObject(int obj)
{
    int index;

    index = 0;
    while (index < OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT &&
        (u32)gObjHitsActiveHitVolumeObjects[index] != 0)
    {
        index = index + 1;
    }
    if (index == OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT)
    {
        gObjHitsActiveHitVolumeObjects[0] = obj;
        return;
    }
    gObjHitsActiveHitVolumeObjects[index] = obj;
    return;
}

void ObjHits_ApplyPairResponse(int objA, int objB, f32 x, f32 y, f32 z, int flag)
{
    ObjAnimComponent* animA;
    ObjAnimComponent* animB;
    ObjHitsPriorityState* stateA;
    ObjHitsPriorityState* stateB;
    f32 localAx;
    f32 localAy;
    f32 localAz;
    f32 localBx;
    f32 localBy;
    f32 localBz;
    int angleA;
    int angleB;
    u32 angle;
    f32 sinVal;
    f32 sinSq;
    f32 weightA;
    f32 weightB;
    f32 sum;
    f32 blend;
    f32 invBlend;

    ObjContact_DispatchCallbacks(objA, objB);
    animA = &((GameObject*)objA)->anim;
    animB = &((GameObject*)objB)->anim;
    stateA = (ObjHitsPriorityState*)animA->hitReactState;
    stateB = (ObjHitsPriorityState*)animB->hitReactState;
    stateA->flags = stateA->flags | 8;
    stateB->flags = stateB->flags | 8;
    *(int*)stateA = objB;
    *(int*)stateB = objA;
    if (animA->parent != NULL)
    {
        Obj_TransformWorldVectorToLocal(x, y, z, &localAx, &localAy, &localAz, *(int*)&animA->parent);
    }
    else
    {
        localAx = x;
        localAy = y;
        localAz = z;
    }
    if (animB->parent != NULL)
    {
        Obj_TransformWorldVectorToLocal(x, y, z, &localBx, &localBy, &localBz, *(int*)&animB->parent);
    }
    else
    {
        localBx = x;
        localBy = y;
        localBz = z;
    }
    if ((animA->classId == 1) && (stateA->lateralResponseWeight != 0) &&
        ((stateB->flags & 0x400) == 0))
    {
        animA->localPosX = animA->localPosX - localAx;
        animA->localPosY = animA->localPosY - localAy;
        animA->localPosZ = animA->localPosZ - localAz;
        if (flag != 0)
        {
            animA->worldPosX = animA->worldPosX - x;
            animA->worldPosY = animA->worldPosY - y;
            animA->worldPosZ = animA->worldPosZ - z;
        }
        else
        {
            Obj_TransformLocalPointToWorld(animA->localPosX, animA->localPosY,
                                           animA->localPosZ, &animA->worldPosX,
                                           &animA->worldPosY, &animA->worldPosZ,
                                           *(int*)&animA->parent);
        }
    }
    else if ((animB->classId == 1) && (stateB->lateralResponseWeight != 0) &&
        ((stateA->flags & 0x400) == 0))
    {
        animB->localPosX = animB->localPosX + localBx;
        animB->localPosY = animB->localPosY + localBy;
        animB->localPosZ = animB->localPosZ + localBz;
        if (flag != 0)
        {
            animB->worldPosX = animB->worldPosX + x;
            animB->worldPosY = animB->worldPosY + y;
            animB->worldPosZ = animB->worldPosZ + z;
        }
        else
        {
            Obj_TransformLocalPointToWorld(animB->localPosX, animB->localPosY,
                                           animB->localPosZ, &animB->worldPosX,
                                           &animB->worldPosY, &animB->worldPosZ,
                                           *(int*)&animB->parent);
        }
    }
    else if (stateB->lateralResponseWeight == 0)
    {
        if (stateA->lateralResponseWeight != 0)
        {
            animA->localPosX = animA->localPosX - localAx;
            animA->localPosY = animA->localPosY - localAy;
            animA->localPosZ = animA->localPosZ - localAz;
            if (flag != 0)
            {
                animA->worldPosX = animA->worldPosX - x;
                animA->worldPosY = animA->worldPosY - y;
                animA->worldPosZ = animA->worldPosZ - z;
            }
            else
            {
                Obj_TransformLocalPointToWorld(animA->localPosX, animA->localPosY,
                                               animA->localPosZ, &animA->worldPosX,
                                               &animA->worldPosY, &animA->worldPosZ,
                                               *(int*)&animA->parent);
            }
        }
    }
    else if (stateA->lateralResponseWeight == 0)
    {
        if (stateB->lateralResponseWeight != 0)
        {
            animB->localPosX = animB->localPosX + localBx;
            animB->localPosY = animB->localPosY + localBy;
            animB->localPosZ = animB->localPosZ + localBz;
            if (flag != 0)
            {
                animB->worldPosX = animB->worldPosX + x;
                animB->worldPosY = animB->worldPosY + y;
                animB->worldPosZ = animB->worldPosZ + z;
            }
            else
            {
                Obj_TransformLocalPointToWorld(animB->localPosX, animB->localPosY,
                                               animB->localPosZ, &animB->worldPosX,
                                               &animB->worldPosY, &animB->worldPosZ,
                                               *(int*)&animB->parent);
            }
        }
    }
    else
    {
        angle = getAngle(-x, -z) & 0xffff;
        angleA = animA->rotX - angle;
        if (angleA > 0x8000)
        {
            angleA -= 0xffff;
        }
        if (angleA < -0x8000)
        {
            angleA += 0xffff;
        }
        angleB = animB->rotX - (int)((angle + 0x8000) & 0xffff);
        if (angleB > 0x8000)
        {
            angleB -= 0xffff;
        }
        if (angleB < -0x8000)
        {
            angleB += 0xffff;
        }
        sinVal = mathCosf((gObjHitsPi * angleA) / gObjHitsAngleHalfPeriod);
        sinSq = sinVal * sinVal;
        weightA = stateA->lateralResponseWeight * sinSq +
            stateA->axialResponseWeight * (gObjHitsScalarOne - sinSq);
        sinVal = mathCosf((gObjHitsPi * angleB) / gObjHitsAngleHalfPeriod);
        sinSq = sinVal * sinVal;
        weightB = stateB->lateralResponseWeight * sinSq +
            stateB->axialResponseWeight * (gObjHitsScalarOne - sinSq);
        if (weightA < weightB * lbl_803DB450)
        {
            weightA = gObjHitsScalarZero;
        }
        else if (weightB < weightA * lbl_803DB450)
        {
            weightB = gObjHitsScalarZero;
        }
        sum = weightA + weightB;
        if (sum > gObjHitsScalarZero)
        {
            blend = weightB / sum;
        }
        else
        {
            blend = gObjHitsScalarZero;
        }
        animA->localPosX = animA->localPosX - localAx * blend;
        animA->localPosY = animA->localPosY - localAy * blend;
        animA->localPosZ = animA->localPosZ - localAz * blend;
        Obj_TransformLocalPointToWorld(animA->localPosX, animA->localPosY,
                                       animA->localPosZ, &animA->worldPosX,
                                       &animA->worldPosY, &animA->worldPosZ,
                                       *(int*)&animA->parent);
        invBlend = gObjHitsScalarOne - blend;
        animB->localPosX = localBx * invBlend + animB->localPosX;
        animB->localPosY = localBy * invBlend + animB->localPosY;
        animB->localPosZ = localBz * invBlend + animB->localPosZ;
        Obj_TransformLocalPointToWorld(animB->localPosX, animB->localPosY,
                                       animB->localPosZ, &animB->worldPosX,
                                       &animB->worldPosY, &animB->worldPosZ,
                                       *(int*)&animB->parent);
    }
}

void ObjHits_DetectObjectPair(int objA, int objB)
{
    ObjHitsPriorityState* stateA;
    ObjHitsPriorityState* stateB;
    char vertical;
    int distInt;
    int distClamped;
    f32 dist;
    f32 sumRadius;
    f32 radiusA;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 radiusB;
    f32 nx;
    f32 ny;
    f32 nz;
    f32 yA;
    f32 yB;
    f32 tmp;
    f32 sx;
    f32 sy;
    f32 sz;
    f32 segSq;
    f32 cx;
    f32 cy;
    f32 cz;

    stateA = (ObjHitsPriorityState*)((GameObject*)objA)->anim.hitReactState;
    stateB = (ObjHitsPriorityState*)((GameObject*)objB)->anim.hitReactState;
    if (stateA->activeHitboxMode != 0) goto end;
    if (stateB->activeHitboxMode != 0) goto end;
    dx = ((GameObject*)objB)->anim.worldPosX - ((GameObject*)objA)->anim.worldPosX;
    yB = ((GameObject*)objB)->anim.worldPosY;
    yA = ((GameObject*)objA)->anim.worldPosY;
    dy = yB - yA;
    dz = ((GameObject*)objB)->anim.worldPosZ - ((GameObject*)objA)->anim.worldPosZ;
    radiusA = stateA->primaryRadius;
    radiusB = stateB->primaryRadius;
    vertical = 0;
    if (((stateB->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0) ||
        ((stateA->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0))
    {
        if (dy > *(f32*)&gObjHitsScalarZero)
        {
            if ((stateA->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0)
            {
                yA = yA + stateA->primaryCapsuleOffsetB;
            }
            else
            {
                yA = yA + radiusA;
            }
            if ((stateB->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0)
            {
                tmp = yB + stateB->primaryCapsuleOffsetA;
            }
            else
            {
                tmp = yB - radiusB;
            }
            if (tmp > yA) goto end;
        }
        else
        {
            if ((stateB->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0)
            {
                yB = yB + stateB->primaryCapsuleOffsetB;
            }
            else
            {
                yB = yB + radiusB;
            }
            if ((stateA->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0)
            {
                tmp = yA + stateA->primaryCapsuleOffsetA;
            }
            else
            {
                tmp = yA - radiusA;
            }
            if (tmp > yB) goto end;
        }
        dy = gObjHitsScalarZero;
        vertical = 1;
    }
    dist = dx * dx + dy * dy + dz * dz;
    if (dist != gObjHitsScalarZero)
    {
        dist = sqrtf(dist);
    }
    distInt = (int)(f32)(int)
    dist;
    distClamped = distInt;
    if (distInt > 0x400)
    {
        distClamped = 0x400;
    }
    if (distClamped <= stateA->capsuleScale)
    {
        stateA->capsuleScale = distClamped;
    }
    if (distInt > 0x400)
    {
        distInt = 0x400;
    }
    if (distInt <= stateB->capsuleScale)
    {
        stateB->capsuleScale = distInt;
    }
    if ((stateB->flags & OBJHITS_PRIORITY_STATE_ENABLED) != 0)
    {
        sumRadius = radiusB + radiusA;
        sx = ((GameObject*)objA)->anim.worldPosX - stateA->worldPosX;
        sy = ((GameObject*)objA)->anim.worldPosY - stateA->worldPosY;
        sz = ((GameObject*)objA)->anim.worldPosZ - stateA->worldPosZ;
        if (vertical != 0)
        {
            sy = gObjHitsScalarZero;
        }
        segSq = sy * sy + sx * sx + sz * sz;
        if (segSq > gObjHitsScalarOne)
        {
            cz = ((GameObject*)objB)->anim.worldPosZ - stateA->worldPosZ;
            cx = ((GameObject*)objB)->anim.worldPosX - stateA->worldPosX;
            cy = ((GameObject*)objB)->anim.worldPosY - stateA->worldPosY;
            segSq = (sy * cy + sx * cx + sz * cz) / segSq;
            if ((segSq >= gObjHitsScalarZero) && (segSq <= gObjHitsScalarOne))
            {
                cz = (segSq * sz + stateA->worldPosZ) - ((GameObject*)objB)->anim.worldPosZ;
                cz = cz * cz;
                cx = (segSq * sx + stateA->worldPosX) - ((GameObject*)objB)->anim.worldPosX;
                cx = cx * cx;
                cy = (segSq * sy + stateA->worldPosY) - ((GameObject*)objB)->anim.worldPosY;
                cy = cy * cy;
                dist = sqrtf(cz + (cx + cy));
            }
        }
        if ((dist < sumRadius) && (dist > gObjHitsScalarZero))
        {
            extern int ObjHits_RecordObjectHit(int obj, int hitObj, u8 priority, u8 hitVolume,
                                               u8 sphereIndex);
            ObjHits_RecordObjectHit(objB, objA, *(u8*)&stateA->objectPairPriority,
                                    stateA->objectPairHitVolume, 0);
            ObjHits_RecordObjectHit(objA, objB, *(u8*)&stateB->objectPairPriority,
                                    stateB->objectPairHitVolume, 0);
            if (((stateB->flags & OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE) == 0) &&
                ((stateA->flags & OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE) == 0))
            {
                nx = stateB->worldPosX - stateA->worldPosX;
                ny = stateB->worldPosY - stateA->worldPosY;
                nz = stateB->worldPosZ - stateA->worldPosZ;
                if (vertical != 0)
                {
                    ny = gObjHitsScalarZero;
                }
                tmp = sqrtf(ny * ny + nx * nx + nz * nz);
                if (tmp > gObjHitsScalarZero)
                {
                    dx = nx / tmp;
                    dy = ny / tmp;
                    dz = nz / tmp;
                }
                else
                {
                    dx = dx / dist;
                    dy = dy / dist;
                    dz = dz / dist;
                }
                dx = dx * (sumRadius - dist);
                dy = dy * (sumRadius - dist);
                dz = dz * (sumRadius - dist);
                ObjHits_ApplyPairResponse(objA, objB, dx, dy, dz, 0);
            }
        }
    }
end:;
}

void ObjHits_CheckSkeletonPair(int objA, int objB, void* hits, void* scratchB, void* scratchC,
                               void* scratchD, void* scratchE, int depth)
{
    ObjHitsPriorityState* objAState;
    ObjHitsPriorityState* objBState;
    int* hitboxBuf;
    u8 shapeFlags;
    int hitCount;
    f32 ratio;
    f32 responseX;
    f32 responseY;
    f32 responseZ;
    f32 outAxial;
    ObjHitsSkeletonHit* bestHit;
    ObjHitsVec3 point;
    f32 response[3];
    ObjHitsVec3 point3D;
    ObjHitsVec3 pointXZ;

    objBState = (ObjHitsPriorityState*)((GameObject*)objB)->anim.hitReactState;
    objAState = (ObjHitsPriorityState*)((GameObject*)objA)->anim.hitReactState;
    if (((*(s8*)&objAState->resetHitboxMode == 0) && (*(s8*)&objBState->resetHitboxMode == 0)) &&
        (objBState->activeHitboxMode == 0))
    {
        switch (objAState->activeHitboxMode)
        {
        case 0:
            hitboxBuf = (int*)ObjHits_GetActiveModel(objA);
            shapeFlags = objBState->shapeFlags;
            if ((shapeFlags & OBJHITBOX_SHAPE_SKELETON_3D) != 0)
            {
                point.x = ((GameObject*)objB)->anim.worldPosX - playerMapOffsetX;
                point.y = ((GameObject*)objB)->anim.worldPosY;
                point.z = ((GameObject*)objB)->anim.worldPosZ - playerMapOffsetZ;
                point3D = point;
                hitCount = ObjHits_CollectSkeletonHits3D(&point3D.x, objBState->primaryRadius,
                                                         (ObjHitsSkeletonJointData*)hitboxBuf[5], hitboxBuf,
                                                         (ObjHitsSkeletonHit*)hits, &bestHit, &outAxial);
                if (hitCount != 0)
                {
                    ratio = (((GameObject*)objB)->anim.hitboxScale * ((GameObject*)objB)->anim.rootMotionScale) /
                        (((GameObject*)objA)->anim.hitboxScale * ((GameObject*)objA)->anim.rootMotionScale);

                    {
                        f32* pos = &point.x;
                        f32 rad = objBState->primaryRadius;
                        ObjHitsSkeletonHit* hh = (ObjHitsSkeletonHit*)hits;
                        ObjHitsSkeletonJointData* jd = (ObjHitsSkeletonJointData*)hitboxBuf[5];
                        int mf = *hitboxBuf;
                        ObjHitsSkeletonHit* bh = bestHit;
                        ObjHits_CalcSkeletonResponse3D(pos, rad, objB, hh, jd, mf,
                                                       bh,
                                                       (ratio < gObjHitsScalarZero)
                                                           ? gObjHitsScalarZero
                                                           : ((ratio > gObjHitsScalarOne) ? gObjHitsScalarOne : ratio),
                                                       outAxial, response);
                    }
                    responseX = response[0];
                    response[0] = (responseX < *(f32*)&gObjHitsResponseClampMin)
                                ? *(f32*)&gObjHitsResponseClampMin
                                : ((responseX > *(f32*)&gObjHitsResponseClampMax) ? *(f32*)&gObjHitsResponseClampMax : responseX);
                    responseY = response[1];
                    response[1] = (responseY < *(f32*)&gObjHitsResponseClampMin)
                                ? *(f32*)&gObjHitsResponseClampMin
                                : ((responseY > *(f32*)&gObjHitsResponseClampMax) ? *(f32*)&gObjHitsResponseClampMax : responseY);
                    responseZ = response[2];
                    response[2] = (responseZ < *(f32*)&gObjHitsResponseClampMin)
                                ? *(f32*)&gObjHitsResponseClampMin
                                : ((responseZ > *(f32*)&gObjHitsResponseClampMax) ? *(f32*)&gObjHitsResponseClampMax : responseZ);
                    ObjHits_ApplyPairResponse(objA, objB, response[0], response[1], (f32)(f64)response[2], 0);
                }
            }
            else if ((shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0)
            {
                point.x = ((GameObject*)objB)->anim.worldPosX - playerMapOffsetX;
                point.y = ((GameObject*)objB)->anim.worldPosY;
                point.z = ((GameObject*)objB)->anim.worldPosZ - playerMapOffsetZ;
                pointXZ = point;
                hitCount = ObjHits_CollectSkeletonHitsXZ(&pointXZ.x, objBState->primaryRadius,
                                                         (ObjHitsSkeletonJointData*)hitboxBuf[5], hitboxBuf,
                                                         (ObjHitsSkeletonHit*)hits, &bestHit,
                                                         point.y + objBState->primaryCapsuleOffsetB,
                                                         point.y + objBState->primaryCapsuleOffsetA,
                                                         &outAxial);
                if (hitCount != 0)
                {
                    ratio = (((GameObject*)objB)->anim.hitboxScale * ((GameObject*)objB)->anim.rootMotionScale) /
                        (((GameObject*)objA)->anim.hitboxScale * ((GameObject*)objB)->anim.rootMotionScale);

                    {
                        f32* pos = &point.x;
                        f32 rad = objBState->primaryRadius;
                        ObjHitsSkeletonHit* hh = (ObjHitsSkeletonHit*)hits;
                        ObjHitsSkeletonJointData* jd = (ObjHitsSkeletonJointData*)hitboxBuf[5];
                        int mf = *hitboxBuf;
                        ObjHitsSkeletonHit* bh = bestHit;
                        ObjHits_CalcSkeletonResponseXZ(pos, rad, objB, hh, jd, mf,
                                                       bh,
                                                       (ratio < gObjHitsScalarZero)
                                                           ? gObjHitsScalarZero
                                                           : ((ratio > gObjHitsScalarOne) ? gObjHitsScalarOne : ratio),
                                                       outAxial, response);
                    }
                    responseX = response[0];
                    response[0] = (responseX < *(f32*)&gObjHitsResponseClampMin)
                                ? *(f32*)&gObjHitsResponseClampMin
                                : ((responseX > *(f32*)&gObjHitsResponseClampMax) ? *(f32*)&gObjHitsResponseClampMax : responseX);
                    responseY = response[1];
                    response[1] = (responseY < *(f32*)&gObjHitsResponseClampMin)
                                ? *(f32*)&gObjHitsResponseClampMin
                                : ((responseY > *(f32*)&gObjHitsResponseClampMax) ? *(f32*)&gObjHitsResponseClampMax : responseY);
                    responseZ = response[2];
                    response[2] = (responseZ < *(f32*)&gObjHitsResponseClampMin)
                                ? *(f32*)&gObjHitsResponseClampMin
                                : ((responseZ > *(f32*)&gObjHitsResponseClampMax) ? *(f32*)&gObjHitsResponseClampMax : responseZ);
                    ObjHits_ApplyPairResponse(objA, objB, response[0], response[1], (f32)(f64)response[2], 0);
                }
            }
            else if (((shapeFlags & OBJHITS_SHAPE_SKELETON) != 0) && (depth < 1))
            {
                ObjHits_CheckSkeletonPair(objB, objA, hits, scratchB, scratchC, scratchD, scratchE,
                                          depth + 1);
            }
            break;
        }
    }
}

#pragma opt_loop_invariants off
void ObjHits_CheckTrackContact(int objA, int objB)
{
    u32 sphereIdx;
    int mask2;
    u8 contact;
    ObjHitsPriorityState* stateA;
    ObjHitsPriorityState* stateB;
    u32 bits;
    float* curWalk;
    ObjHitsModelBank* modelBank;
    int volOff;
    int prevWalk;
    int i;
    ObjHitsModelFileHeader* modelFile;
    float* curSpheres;
    int prevSpheres;
    int rOff;
    int ptOff;
    float* curEntry;
    int prevEntry;
    int pointCount;
    ObjHitsModelHitVolume* hitVolume;
    u32 bounds[6];
    struct
    {
        u8 out[64];
        f32 radii[4];
        u8 ids[4];
        u8 sevens[4];
        u8 pad58[4];
        int kinds[5];
    } hb;
    float endPoints[18];
    float startPoints[18];
    f32 fConv;

    stateA = (ObjHitsPriorityState*)((GameObject*)objA)->anim.hitReactState;
    mask2 = (u32)objB == objA
                ? stateA->objectHitMask >> 4
                : stateA->objectHitMask & 0xf;
    if ((mask2 != 0) && (*(s8*)&stateA->suppressOutgoingHits == 0))
    {
        stateB = (ObjHitsPriorityState*)((GameObject*)objB)->anim.hitReactState;
        if ((stateB->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) != 0)
        {
            modelBank = ObjHits_GetActiveModel(objB);
            modelFile = modelBank->modelFile;
            bits = modelBank->hitBufferFlags >> 2 & 1;
            curSpheres = modelBank->hitVolumeSphereBuffers[bits];
            prevSpheres = (int)modelBank->hitVolumeSphereBuffers[bits ^ 1];
            pointCount = 0;
            rOff = 0;
            ptOff = 0;
            volOff = 0;
            curWalk = curSpheres;
            prevWalk = prevSpheres;
            for (i = 0; i < (int)(u32)modelFile->hitVolumeCount; i = i + 1)
            {
                hitVolume = (ObjHitsModelHitVolume*)((u8*)modelFile->hitVolumes + volOff);
                if ((i == hitVolume->sphereIndex) &&
                    ((mask2 & 1 << hitVolume->maskBit) != 0))
                {
                    bits = hitVolume->linkedSpheres;
                    if (bits != 0)
                    {
                        float* endPtr = (float*)((int)endPoints + ptOff);
                        float* startPtr = (float*)((int)startPoints + ptOff);
                        u8* radPtr = (u8*)&hb + rOff;
                        u8* idPtr = (u8*)&hb + pointCount;
                        f32 offX = playerMapOffsetX;
                        f32 offZ = playerMapOffsetZ;
                        for (; (u16)bits != 0; bits = (u16)((u16)bits << 4))
                        {
                            sphereIdx = (((u16)bits & 0xf000) >> 0xc) + i & 0xffff;
                            if (pointCount < 4)
                            {
                                curEntry = curSpheres + sphereIdx * 4;
                                *endPtr = offX + curEntry[1];
                                endPtr[1] = curEntry[2];
                                endPtr[2] = offZ + curEntry[3];
                                prevEntry = prevSpheres + sphereIdx * 0x10;
                                *startPtr = offX + *(float*)(prevEntry + 4);
                                startPtr[1] = *(float*)(prevEntry + 8);
                                startPtr[2] = offZ + *(float*)(prevEntry + 0xc);
                                *(float*)(radPtr + 0x40) = *curEntry;
                                *(s8*)(idPtr + 0x50) = -1;
                                *(idPtr + 0x54) = 7;
                                endPtr = endPtr + 3;
                                startPtr = startPtr + 3;
                                radPtr = radPtr + 4;
                                idPtr = idPtr + 1;
                                pointCount = pointCount + 1;
                                rOff = rOff + 4;
                                ptOff = ptOff + 0xc;
                            }
                        }
                    }
                    else
                    {
                        if (pointCount < 4)
                        {
                            *(float*)((int)endPoints + ptOff) = playerMapOffsetX + curWalk[1];
                            *(float*)((int)endPoints + ptOff + 4) = curWalk[2];
                            *(float*)((int)endPoints + ptOff + 8) = playerMapOffsetZ + curWalk[3];
                            *(float*)((int)startPoints + ptOff) = playerMapOffsetX + *(float*)(prevWalk + 4);
                            *(float*)((int)startPoints + ptOff + 4) = *(float*)(prevWalk + 8);
                            *(float*)((int)startPoints + ptOff + 8) = playerMapOffsetZ + *(float*)(prevWalk + 0xc);
                            *(float*)(((u8*)&hb + rOff) + 0x40) = *curWalk;
                            *(s8*)(((u8*)&hb + 0x50) + pointCount) = -1;
                            *(((u8*)&hb + 0x54) + pointCount) = 7;
                            pointCount = pointCount + 1;
                            rOff = rOff + 4;
                            ptOff = ptOff + 0xc;
                        }
                    }
                }
                volOff = volOff + OBJHITS_MODEL_HIT_VOLUME_SIZE;
                curWalk = curWalk + 4;
                prevWalk = prevWalk + 0x10;
            }
        }
        else
        {
            endPoints[0] = ((GameObject*)objA)->anim.worldPosX;
            endPoints[1] = ((GameObject*)objA)->anim.worldPosY;
            endPoints[2] = ((GameObject*)objA)->anim.worldPosZ;
            startPoints[0] = ((GameObject*)objA)->anim.previousWorldPosX;
            startPoints[1] = ((GameObject*)objA)->anim.previousWorldPosY;
            startPoints[2] = ((GameObject*)objA)->anim.previousWorldPosZ;
            fConv = (f32)(u32)((GameObject*)objA)->anim.modelInstance->fallbackHitSphereRadius;
            if (fConv < lbl_803DE91C)
            {
                fConv = lbl_803DE91C;
            }
            hb.radii[0] = fConv;
            *(s8*)&hb.ids[0] = -1;
            hb.sevens[0] = 7;
            pointCount = 1;
        }
        if (pointCount != 0)
        {
            hitDetect_calcSweptSphereBounds(bounds, startPoints, endPoints, hb.radii, pointCount);
            hitDetectFn_800691c0(objB, bounds, stateB->trackContactMask, 1);
            contact = hitDetectFn_80067958(objB, startPoints, endPoints, pointCount, hb.out, 0);
            if (contact != 0)
            {
                if ((contact & 1) != 0)
                {
                    pointCount = 0;
                }
                else if ((contact & 2) != 0)
                {
                    pointCount = 1;
                }
                else if ((contact & 4) != 0)
                {
                    pointCount = 2;
                }
                else
                {
                    pointCount = 3;
                }
                stateB->contactHitVolume = ((s8*)hb.ids)[pointCount];
                stateB->contactPosX = endPoints[pointCount * 3];
                stateB->contactPosY = endPoints[pointCount * 3 + 1];
                stateB->contactPosZ = endPoints[pointCount * 3 + 2];
                if (hb.kinds[pointCount] != 0u)
                {
                    stateB->contactFlags = stateB->contactFlags | 2;
                }
                else
                {
                    stateB->contactFlags = stateB->contactFlags | 1;
                }
            }
        }
    }
}
#pragma opt_loop_invariants reset

void ObjHits_Update(int objectCount)
{
    u8 skeletonScratchB[1052];
    u8 skeletonScratchC[1040];
    u8 skeletonHits[1512];
    u8 skeletonScratchD[100];
    u8 skeletonScratchE[100];
    int listCount;
    int startIndex;
    int* objectList;
    ObjHitsSweepEntry* sweepEntries;
    ObjHitsSweepEntry* nextEntry;
    ObjHitsSweepEntry** entrySlotBase;
    ObjHitsSweepEntry** entrySlot;
    ObjHitsSweepEntry* entry;
    ObjHitsSweepEntry* candidateEntry;
    int obj;
    int candObj;
    u32 attachedObj;
    u32 candAttachedObj;
    ObjHitsPriorityState* objState;
    ObjHitsPriorityState* candState;
    int slotCount;
    int slotIndex;
    int currentIndex;
    int candidateIndex;
    f32 axisDiff;
    f32 diff;

    objectList = ObjList_GetObjects(&startIndex, &listCount);
    sweepEntries = gObjHitsSweepEntries;
    sweepEntries->minX = gObjHitsSweepSortSentinel;
    sweepEntries->maxX = gObjHitsSweepSortSentinel;
    gObjHitsSweepEntryPtrs[0] = sweepEntries;
    slotCount = 1;
    nextEntry = &sweepEntries[1];
    entrySlotBase = &gObjHitsSweepEntryPtrs[1];
    entrySlot = entrySlotBase;
    for (; objectCount > 0; objectCount--)
    {
        {
            obj = *objectList;
            objState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (objState != NULL)
            {
                if (((objState->flags &
                        (OBJHITS_PRIORITY_STATE_ENABLED |
                            OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE)) != 0) &&
                    (objState->shapeFlags != 8) && (slotCount < OBJHITS_SWEEP_ENTRY_CAPACITY))
                {
                    *entrySlot = nextEntry;
                    (*entrySlot)->obj = obj;
                    (*entrySlot)->minX = ((GameObject*)obj)->anim.worldPosX - objState->sweepRadiusX;
                    nextEntry++;
                    entrySlot++;
                    gObjHitsSweepEntryPtrs[slotCount++]->maxX = ((GameObject*)obj)->anim.worldPosX + objState->
                        sweepRadiusX;
                }
                objState->flags = objState->flags & ~OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED;
                objState->contactFlags = 0;
                *(s8*)&objState->contactHitVolume = -1;
                *(int*)objState = 0;
                attachedObj = *(u32*)&((GameObject*)obj)->childObjs[0];
                if ((attachedObj != 0) && (((GameObject*)attachedObj)->anim.classId == 0x2d))
                {
                    objState = ObjAnim_GetPriorityHitState((ObjAnimComponent*)attachedObj);
                    objState->flags = objState->flags & ~OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED;
                    objState->contactFlags = 0;
                    *(s8*)&objState->contactHitVolume = -1;
                    *(int*)objState = 0;
                }
            }
            objectList++;
        }
    }
    ObjHits_SortSweepEntries(gObjHitsSweepEntryPtrs, slotCount);
    currentIndex = 1;
    slotIndex = 1;
    entrySlot = entrySlotBase;
    for (; slotIndex < slotCount; slotIndex++, entrySlot++)
    {
        entry = *entrySlot;
        obj = entry->obj;
        objState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        attachedObj = *(u32*)&((GameObject*)obj)->childObjs[0];
        if ((attachedObj != 0) &&
            ((ObjAnim_GetPriorityHitState((ObjAnimComponent*)attachedObj) == NULL) ||
                ((ObjAnim_GetPriorityHitState((ObjAnimComponent*)attachedObj)->flags &
                    OBJHITS_PRIORITY_STATE_ENABLED) == 0)))
        {
            attachedObj = 0;
        }
        if ((objState->flags & 4) != 0)
        {
            ObjHitsSweepEntry** skipSlot;
            candidateIndex = currentIndex;
            skipSlot = &gObjHitsSweepEntryPtrs[currentIndex];
            for (; (entry->minX > (*skipSlot)->maxX) && (candidateIndex < slotCount); candidateIndex++)
            {
                skipSlot++;
            }
            currentIndex = candidateIndex;
            for (; (candidateIndex < slotCount) &&
                   ((*entrySlot)->maxX > gObjHitsSweepEntryPtrs[candidateIndex]->minX);
                   candidateIndex++)
            {
                candidateEntry = gObjHitsSweepEntryPtrs[candidateIndex];
                if ((*entrySlot)->minX > candidateEntry->maxX)
                {
                    continue;
                }
                {
                    candObj = candidateEntry->obj;
                    candState = ObjAnim_GetPriorityHitState((ObjAnimComponent*)candObj);
                    if ((slotIndex != candidateIndex) &&
                        ((u32)((GameObject*)obj)->anim.parent != candObj))
                    {
                        axisDiff = ((GameObject*)obj)->anim.worldPosZ -
                            ((GameObject*)candObj)->anim.worldPosZ;
                        if (axisDiff > gObjHitsScalarZero)
                        {
                            diff = axisDiff;
                        }
                        else
                        {
                            diff = -axisDiff;
                        }
                        if (diff < objState->primaryRadiusXZ + candState->primaryRadiusXZ)
                        {
                            axisDiff = ((GameObject*)obj)->anim.worldPosY -
                                ((GameObject*)candObj)->anim.worldPosY;
                            if (axisDiff > *(const f32*)&gObjHitsScalarZero)
                            {
                                diff = axisDiff;
                            }
                            else
                            {
                                diff = -axisDiff;
                            }
                            if ((diff < objState->primaryRadiusY + candState->primaryRadiusY) &&
                                ((objState->flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0) &&
                                ((candState->flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0) &&
                                (((candState->flags & 4) == 0) || (slotIndex >= candidateIndex)) &&
                                ((((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask & candState->targetMask) !=
                                    0) &&
                                ((((GameObject*)candObj)->anim.modelInstance->runtimeSourceHitMask & objState->targetMask)
                                    != 0))
                            {
                                if ((candState->shapeFlags & OBJHITS_SHAPE_SKELETON) != 0)
                                {
                                    ((void (*)(int, int, void*, void*, void*, void*, void*, int))
                                        ObjHits_CheckSkeletonPair)(candObj, obj, skeletonHits, skeletonScratchB,
                                                                   skeletonScratchC, skeletonScratchD,
                                                                   skeletonScratchE, 0);
                                }
                                else if ((objState->shapeFlags & OBJHITS_SHAPE_SKELETON) != 0)
                                {
                                    ((void (*)(int, int, void*, void*, void*, void*, void*, int))
                                        ObjHits_CheckSkeletonPair)(obj, candObj, skeletonHits, skeletonScratchB,
                                                                   skeletonScratchC, skeletonScratchD,
                                                                   skeletonScratchE, 0);
                                }
                                else if ((objState->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES) ||
                                    (candState->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES))
                                {
                                    if ((objState->lateralResponseWeight != 0) ||
                                        (candState->lateralResponseWeight != 0))
                                    {
                                        ObjHits_CheckHitVolumes(obj, candObj, obj, 0, 1, 0xffffffff, 0);
                                    }
                                }
                                else if ((objState->lateralResponseWeight != 0) ||
                                    (candState->lateralResponseWeight != 0))
                                {
                                    ObjHits_DetectObjectPair(obj, candObj);
                                }
                            }
                        }
                        if (diff < objState->secondaryRadiusXZ + candState->secondaryRadiusXZ)
                        {
                            axisDiff = (((GameObject*)obj)->anim.worldPosY -
                                            ((GameObject*)candObj)->anim.worldPosY >
                                        gObjHitsScalarZero)
                                           ? ((GameObject*)obj)->anim.worldPosY -
                                                 ((GameObject*)candObj)->anim.worldPosY
                                           : -(((GameObject*)obj)->anim.worldPosY -
                                               ((GameObject*)candObj)->anim.worldPosY);
                            if ((axisDiff < objState->secondaryRadiusY + candState->secondaryRadiusY) &&
                                ((objState->flags & 0x100) == 0) && ((candState->flags & 0x100) == 0) &&
                                ((objState->sourceMask & candState->targetMask) != 0) &&
                                (((candState->sourceMask & 0x80) != 0) ||
                                    ((candState->sourceMask & objState->targetMask) != 0)))
                            {
                                candAttachedObj = (u32)((GameObject*)candObj)->childObjs[0];
                                if ((candAttachedObj != 0) &&
                                    ((ObjAnim_GetPriorityHitState((ObjAnimComponent*)candAttachedObj) == NULL) ||
                                        ((ObjAnim_GetPriorityHitState((ObjAnimComponent*)candAttachedObj)->flags &
                                            OBJHITS_PRIORITY_STATE_ENABLED) == 0)))
                                {
                                    candAttachedObj = 0;
                                }
                                ObjHits_CheckObjectHitVolumes(obj, candObj, attachedObj, candAttachedObj,
                                                              timeDelta);
                            }
                        }
                    }
                }
            }
        }
    }
    entrySlot = entrySlotBase;
    for (slotIndex = 1; slotIndex < slotCount; slotIndex++, entrySlot++)
    {
        obj = (*entrySlot)->obj;
        if (((((GameObject*)obj)->anim.hitReactState)->flags &
            OBJHITS_PRIORITY_STATE_TRACK_CONTACT) != 0)
        {
            ObjHits_CheckTrackContact(obj, obj);
            attachedObj = (u32)((GameObject*)obj)->childObjs[0];
            if (attachedObj != 0)
            {
                ObjHits_CheckTrackContact(obj, attachedObj);
            }
        }
    }
    for (slotIndex = 1; slotIndex < slotCount; slotIndex++, entrySlotBase++)
    {
        obj = (*entrySlotBase)->obj;
        objState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        objState->localPosX = ((GameObject*)obj)->anim.localPosX;
        objState->localPosY = ((GameObject*)obj)->anim.localPosY;
        objState->localPosZ = ((GameObject*)obj)->anim.localPosZ;
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            Obj_TransformLocalPointToWorld(objState->localPosX, objState->localPosY, objState->localPosZ,
                                           &objState->worldPosX, &objState->worldPosY,
                                           &objState->worldPosZ, (int)((GameObject*)obj)->anim.parent);
        }
        else
        {
            objState->worldPosX = ((GameObject*)obj)->anim.localPosX;
            objState->worldPosY = ((GameObject*)obj)->anim.localPosY;
            objState->worldPosZ = ((GameObject*)obj)->anim.localPosZ;
        }
        objState->activeHitboxMode = 0;
        objState->flags = objState->flags & ~OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED;
        if (((objState->priorityHitCount != 0) ||
                ((objState->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED) != 0)) &&
            ((objState->flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0) &&
            ((objState->flags & 0x4000) == 0))
        {
            ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)
                obj)->anim.previousLocalPosX);
            ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject*)
                obj)->anim.previousLocalPosZ);
        }
    }
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[slotIndex = 0] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++slotIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++slotIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++slotIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++slotIndex] = 0;
}
