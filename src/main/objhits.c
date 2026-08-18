#define OBJHITS_SETTERS_S16
#define OBJHITS_STATE_INDEX_S8
#include <string.h>
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/model.h"
#include "main/obj_contact.h"
#include "main/obj_list.h"
#include "main/objhits.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "main/track_dolphin_api.h"
#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/mm.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objHitReact_types.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/resource.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/mtx.h"
#include "main/dll/objpathtransform_struct.h"
#include "main/game_ui_interface.h"
#include "main/lightmap_api.h"
#include "main/dll/player_api.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/objtype.h"
#include "main/obj_hit_region.h"
#include "main/obj_link.h"
#include "main/objlib_api.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/obj_trigger.h"
#include "main/player_eye_anim.h"
#include "main/pad_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/texture.h"
#include "main/objprint_dolphin_api.h"
#include "main/curve_eval.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/newshadows.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/dll/modgfx.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "main/acosf.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"
#include "main/objprint_internal.h"
#include "main/objprint_render_api.h"

const f32 gObjHitsScalarZero[1] = {0.0f};
const f32 gObjHitsScalarTwo[1] = {2.0f};
const f32 gObjHitsScalarOne[1] = {1.0f};
const f32 gObjHitsScalarTenth[1] = {0.1f};

GameObject* gObjHitsActiveHitVolumeObjects[OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT] = {NULL};
ObjHitsSweepEntry* gObjHitsSweepEntryPtrs[OBJHITS_SWEEP_ENTRY_CAPACITY];
extern ObjHitsSweepEntry gObjHitsSweepEntries[OBJHITS_SWEEP_ENTRY_CAPACITY];
extern ObjHitsPriorityWorkSlot* gObjHitsPriorityHitStates;
extern void* gObjHitsWorkBuffer;
extern f32 gObjHitsResponseDominanceRatio;

extern f32 gObjHitsPriorityHitTickDelta;
static inline ObjModel* ObjHits_GetActiveModel(GameObject* obj) {
    ObjAnimComponent* objAnim = &obj->anim;
    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

int ObjHits_CollectSkeletonHitsXZ(f32* point, f32 radius, ModelJointWork* jointData, int* model,
                                  ObjHitsSkeletonHit* hits, ObjHitsSkeletonHit** outBest, f32 yMax, f32 yMin,
                                  f32* outAccum) {
    float doubledPointX;
    float doubledPointZ;
    float diameter;
    float rootCullDistance;
    float* radii;
    int joint;
    int parent;
    int hitCount;
    ModelFileHeader* modelFile;
    ObjHitsSkeletonHit* hit;
    ObjModelJointMatrix* jointMatrix;
    float dx;
    float dz;
    float jointRadius;
    float parentRadius;
    float doubledMidpointDeltaX;
    float doubledMidpointDeltaZ;
    float maxJointDiameter;
    float broadPhaseLimit;
    float jointLength;
    float inverseJointLength;
    float distanceMagnitude;
    Vec jointPos;
    Vec parentPos;
    Vec axisDir;
    float axial;
    float distSq;
    float radSum;

    hitCount = 0;
    if (jointData == NULL) {
        return 0;
    }
    modelFile = *(ModelFileHeader**)model;
    radii = jointData->jointRadii;
    diameter = radius + radius;
    hit = hits;
    *outBest = hits;
    *outAccum = gObjHitsScalarZero[0];
    jointMatrix = ObjModel_GetJointMatrix((u8*)model, 0);
    jointPos.x = jointMatrix->translationX;
    jointPos.y = jointMatrix->translationY;
    jointPos.z = jointMatrix->translationZ;
    dx = jointPos.x - point[0];
    dz = jointPos.z - point[2];
    rootCullDistance = sqrtf(dx * dx + gObjHitsScalarZero[0] + dz * dz) - radius;
    doubledPointX = point[0] + point[0];
    doubledPointZ = point[2] + point[2];
    joint = modelFile->jointCount;
    while (--joint != 0) {
        if (jointData->jointCullDistances[joint] > rootCullDistance) {
            parent = ((ModelBone*)modelFile->jointData)[joint].parent;
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
            jointRadius = radii[joint];
            parentRadius = radii[parent];
            if ((!(jointPos.y - jointRadius > yMax) || !(parentPos.y - parentRadius > yMax)) &&
                (!(jointPos.y + jointRadius < yMin) || !(parentPos.y + parentRadius < yMin))) {
                doubledMidpointDeltaX = (parentPos.x + jointPos.x) - doubledPointX;
                doubledMidpointDeltaZ = (parentPos.z + jointPos.z) - doubledPointZ;
                broadPhaseLimit = jointData->jointLengths[joint];
                if (jointRadius > parentRadius) {
                    maxJointDiameter = jointRadius + jointRadius;
                } else {
                    maxJointDiameter = parentRadius + parentRadius;
                }
                broadPhaseLimit = diameter + (broadPhaseLimit + maxJointDiameter);
                broadPhaseLimit = broadPhaseLimit * broadPhaseLimit;
                if (doubledMidpointDeltaX * doubledMidpointDeltaX + gObjHitsScalarZero[0] +
                        doubledMidpointDeltaZ * doubledMidpointDeltaZ <
                    broadPhaseLimit) {
                    axisDir.x = parentPos.x - jointPos.x;
                    axisDir.y = parentPos.y - jointPos.y;
                    axisDir.z = parentPos.z - jointPos.z;
                    jointLength = jointData->jointLengths[joint];
                    if (jointLength != gObjHitsScalarZero[0]) {
                        inverseJointLength = gObjHitsScalarOne[0] / jointLength;
                        axisDir.x = axisDir.x * inverseJointLength;
                        axisDir.y = axisDir.y * inverseJointLength;
                        axisDir.z = axisDir.z * inverseJointLength;
                    }
                    jointData->touchedJoints[joint] = 0;
                    jointData->touchedJoints[parent] = 0;
                    if (ObjHits_TestTaperedCapsuleXZ(point, radius, jointRadius, parentRadius, &jointPos.x, &axisDir.x,
                                                     &parentPos.x, jointData->jointLengths[joint], &axial, &distSq,
                                                     &radSum) != 0) {
                        jointData->touchedJoints[joint] = 1;
                        jointData->touchedJoints[parent] = 1;
                        hit->signedSurfaceDistance = radius + (sqrtf(distSq) - radSum);
                        if (gObjHitsScalarZero[0] == hit->signedSurfaceDistance) {
                            hit->signedSurfaceDistance = 1e-06f;
                        }
                        distanceMagnitude = (hit->signedSurfaceDistance > gObjHitsScalarZero[0])
                                                ? hit->signedSurfaceDistance
                                                : -hit->signedSurfaceDistance;
                        hit->inverseDistance = gObjHitsScalarOne[0] / distanceMagnitude;
                        *outAccum = *outAccum + hit->inverseDistance;
                        if (hit->signedSurfaceDistance < (*outBest)->signedSurfaceDistance) {
                            *outBest = hit;
                        }
                        hit->pointARef = &jointPos.x;
                        hit->pointBRef = &parentPos.x;
                        hit->pointA[0] = jointPos.x;
                        hit->pointA[1] = jointPos.y;
                        hit->pointA[2] = jointPos.z;
                        hit->pointB[0] = parentPos.x;
                        hit->pointB[1] = parentPos.y;
                        hit->pointB[2] = parentPos.z;
                        hit->capsuleAxial = axial;
                        hit->radiusSum = radSum;
                        hit->centerDistance = sqrtf(distSq);
                        hit->axisDir[0] = axisDir.x;
                        hit->axisDir[1] = axisDir.y;
                        hit->axisDir[2] = axisDir.z;
                        hit->pointIndexA = joint;
                        hit->pointIndexB = parent;
                        if (hitCount < OBJHITS_SKELETON_HIT_CAPACITY) {
                            hit += 1;
                            hitCount += 1;
                        }
                    }
                }
            }
        }
    }
    hit->pointIndexA = OBJHITS_SKELETON_HIT_SENTINEL;
    return hit != hits;
}
int ObjHits_CollectSkeletonHits3D(f32* point, f32 radius, ModelJointWork* jointData, int* model,
                                  ObjHitsSkeletonHit* hits, ObjHitsSkeletonHit** outBest, f32* outAccum) {
    float doubledPointX;
    float doubledPointZ;
    float diameter;
    float rootCullDistance;
    float* radii;
    int joint;
    int parent;
    int hitCount;
    ObjHitsSkeletonHit* hit;
    ModelFileHeader* modelFile;
    ObjModelJointMatrix* jointMatrix;
    float dx;
    float dz;
    float jointRadius;
    float parentRadius;
    float doubledMidpointDeltaX;
    float doubledMidpointDeltaZ;
    float maxJointDiameter;
    float broadPhaseLimit;
    float inverseJointLength;
    float distanceMagnitude;
    Vec jointPos;
    Vec parentPos;
    Vec axisDir;
    float axial;
    float distSq;
    float radSum;

    hitCount = 0;
    if (jointData == NULL) {
        return 0;
    }
    modelFile = *(ModelFileHeader**)model;
    radii = jointData->jointRadii;
    diameter = radius + radius;
    hit = hits;
    *outBest = hits;
    *outAccum = gObjHitsScalarZero[0];
    jointMatrix = ObjModel_GetJointMatrix((u8*)model, 0);
    jointPos.x = jointMatrix->translationX;
    jointPos.y = jointMatrix->translationY;
    jointPos.z = jointMatrix->translationZ;
    dx = jointPos.x - point[0];
    dz = jointPos.z - point[2];
    rootCullDistance = sqrtf(dx * dx + gObjHitsScalarZero[0] + dz * dz) - radius;
    doubledPointX = point[0] + point[0];
    doubledPointZ = point[2] + point[2];
    joint = modelFile->jointCount;
    while (--joint != 0) {
        if (jointData->jointCullDistances[joint] > rootCullDistance) {
            parent = ((ModelBone*)modelFile->jointData)[joint].parent;
            jointMatrix = ObjModel_GetJointMatrix((u8*)model, joint);
            jointPos.x = jointMatrix->translationX;
            jointPos.y = jointMatrix->translationY;
            jointPos.z = jointMatrix->translationZ;
            jointMatrix = ObjModel_GetJointMatrix((u8*)model, parent);
            parentPos.x = jointMatrix->translationX;
            parentPos.y = jointMatrix->translationY;
            parentPos.z = jointMatrix->translationZ;
            jointRadius = radii[joint];
            parentRadius = radii[parent];
            jointData->touchedJoints[joint] = 1;
            jointData->touchedJoints[parent] = 1;
            doubledMidpointDeltaX = (parentPos.x + jointPos.x) - doubledPointX;
            doubledMidpointDeltaZ = (parentPos.z + jointPos.z) - doubledPointZ;
            broadPhaseLimit = jointData->jointLengths[joint];
            if (jointRadius > parentRadius) {
                maxJointDiameter = jointRadius + jointRadius;
            } else {
                maxJointDiameter = parentRadius + parentRadius;
            }
            broadPhaseLimit = diameter + (broadPhaseLimit + maxJointDiameter);
            broadPhaseLimit = broadPhaseLimit * broadPhaseLimit;
            if (doubledMidpointDeltaX * doubledMidpointDeltaX + gObjHitsScalarZero[0] +
                    doubledMidpointDeltaZ * doubledMidpointDeltaZ <
                broadPhaseLimit) {
                axisDir.x = parentPos.x - jointPos.x;
                axisDir.y = parentPos.y - jointPos.y;
                axisDir.z = parentPos.z - jointPos.z;
                inverseJointLength = gObjHitsScalarOne[0] / jointData->jointLengths[joint];
                axisDir.x = axisDir.x * inverseJointLength;
                axisDir.y = axisDir.y * inverseJointLength;
                axisDir.z = axisDir.z * inverseJointLength;
                if (ObjHits_TestTaperedCapsule3D(point, radius, jointRadius, parentRadius, &jointPos.x, &axisDir.x,
                                                 &parentPos.x, jointData->jointLengths[joint], &axial, &distSq,
                                                 &radSum) != 0) {
                    jointData->touchedJoints[joint] = 1;
                    jointData->touchedJoints[parent] = 1;
                    hit->signedSurfaceDistance = radius + (sqrtf(distSq) - radSum);
                    if (gObjHitsScalarZero[0] == hit->signedSurfaceDistance) {
                        hit->signedSurfaceDistance = 1e-06f;
                    }
                    distanceMagnitude = (hit->signedSurfaceDistance > gObjHitsScalarZero[0]) ? hit->signedSurfaceDistance
                                                                                          : -hit->signedSurfaceDistance;
                    hit->inverseDistance = gObjHitsScalarOne[0] / distanceMagnitude;
                    *outAccum = *outAccum + hit->inverseDistance;
                    if (hit->signedSurfaceDistance < (*outBest)->signedSurfaceDistance) {
                        *outBest = hit;
                    }
                    hit->pointARef = &jointPos.x;
                    hit->pointBRef = &parentPos.x;
                    hit->pointA[0] = jointPos.x;
                    hit->pointA[1] = jointPos.y;
                    hit->pointA[2] = jointPos.z;
                    hit->pointB[0] = parentPos.x;
                    hit->pointB[1] = parentPos.y;
                    hit->pointB[2] = parentPos.z;
                    hit->capsuleAxial = axial;
                    hit->radiusSum = radSum;
                    hit->centerDistance = sqrtf(distSq);
                    hit->axisDir[0] = axisDir.x;
                    hit->axisDir[1] = axisDir.y;
                    hit->axisDir[2] = axisDir.z;
                    hit->pointIndexA = joint;
                    hit->pointIndexB = parent;
                    if (hitCount < OBJHITS_SKELETON_HIT_CAPACITY) {
                        hitCount += 1;
                        hit += 1;
                    }
                }
            }
        }
    }
    hit->pointIndexA = OBJHITS_SKELETON_HIT_SENTINEL;
    return hit != hits;
}

int ObjHits_CalcSkeletonResponseXZ(f32* pos, f32 radius, GameObject* obj, ObjHitsSkeletonHit* hits,
                                   ModelJointWork* jointPoints, int jointModel, ObjHitsSkeletonHit* bestHit,
                                   f32 t, f32 axial, f32* out) {
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
    struct {
        float out[9];
        Vec accum;
    } pj;
    float reflect[3];
    float normalOut[3];
    Vec normAccum;
    Vec diff;
    Vec move;
    Vec projPos;

    aPtr = &pj.out[9];
    saved = hits;
    move.x = obj->anim.worldPosX - obj->anim.previousWorldPosX;
    move.y = obj->anim.localPosY - obj->anim.previousWorldPosY;
    move.z = obj->anim.worldPosZ - obj->anim.previousWorldPosZ;
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
    pj.accum.x = gObjHitsScalarZero[0];
    pj.accum.y = gObjHitsScalarZero[0];
    pj.accum.z = gObjHitsScalarZero[0];
    normAccum.x = gObjHitsScalarZero[0];
    normAccum.y = gObjHitsScalarZero[0];
    normAccum.z = gObjHitsScalarZero[0];
    Vec3_Normalize(ObjHits_CalcTaperedCapsuleNormal(&projPos.x, bestHit->capsuleAxial, bestHit->pointA, bestHit->pointB,
                                                    jointPoints->jointRadii[bestHit->pointIndexA],
                                                    jointPoints->jointRadii[bestHit->pointIndexB],
                                                    jointPoints->jointLengths[bestHit->pointIndexA], normalOut));
    pPtr = pj.out;
    zf = 0.0f;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1) {
        pb = ObjHits_ProjectPointToTaperedCapsuleXZ(
            &projPos.x, radius, hits->capsuleAxial, hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
            jointPoints->jointRadii[hits->pointIndexB], jointPoints->jointLengths[idxA], pPtr);
        if (axial > zf) {
            hits->inverseDistance = hits->inverseDistance / axial;
        } else {
            hits->inverseDistance = zf;
        }
        pb[0] = pb[0] * hits->inverseDistance;
        pb[1] = pb[1] * hits->inverseDistance;
        pb[2] = pb[2] * hits->inverseDistance;
        pj.accum.x = pj.accum.x + pb[0];
        pj.accum.y = pj.accum.y + pb[1];
        pj.accum.z = pj.accum.z + pb[2];
        norm = ObjHits_CalcTaperedCapsuleNormal(
            pos, hits->capsuleAxial, hits->pointA, hits->pointB, jointPoints->jointRadii[hits->pointIndexA],
            jointPoints->jointRadii[hits->pointIndexB], jointPoints->jointLengths[hits->pointIndexA], normalOut);
        Vec3_Normalize(norm);
        normAccum.x = normAccum.x + norm[0];
        normAccum.y = normAccum.y + norm[1];
        normAccum.z = normAccum.z + norm[2];
    }
    Vec3_Normalize(&normAccum.x);
    diff.x = pj.accum.x - projPos.x;
    diff.y = gObjHitsScalarZero[0];
    diff.z = pj.accum.z - projPos.z;
    axial = Vec3_Length(&diff.x);
    diff.x = pj.accum.x - pos[0];
    diff.y = gObjHitsScalarZero[0];
    diff.z = pj.accum.z - pos[2];
    Vec3_Normalize(&move.x);
    if (moveLen > axial) {
        f32 responseSpan = 0.25f;

        tdiff = gObjHitsScalarOne[0] - t;
        t = 0.75 + tdiff * responseSpan;
        move.x = move.x * (t * (moveLen - axial));
        move.y = move.y * (t * (moveLen - axial));
        move.z = move.z * (t * (moveLen - axial));
        Vec3_ReflectAgainstNormal(&normAccum.x, &move.x, rPtr = reflect);
    } else {
        rPtr = reflect;
        rPtr[0] = gObjHitsScalarZero[0];
        rPtr[1] = gObjHitsScalarZero[0];
        rPtr[2] = gObjHitsScalarZero[0];
    }
    pj.accum.x = pj.accum.x + rPtr[0];
    pj.accum.y = pj.accum.y + rPtr[1];
    pj.accum.z = pj.accum.z + rPtr[2];
    rPtr[0] = gObjHitsScalarZero[0];
    rPtr[1] = gObjHitsScalarZero[0];
    rPtr[2] = gObjHitsScalarZero[0];
    hits = saved;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1) {
        pb = ObjHits_ProjectPointToTaperedCapsuleXZ(
            aPtr, radius, hits->capsuleAxial, hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
            jointPoints->jointRadii[hits->pointIndexB], jointPoints->jointLengths[idxA], pPtr);
        pb[0] = pb[0] * hits->inverseDistance;
        pb[1] = pb[1] * hits->inverseDistance;
        pb[2] = pb[2] * hits->inverseDistance;
        rPtr[0] = rPtr[0] + pb[0];
        rPtr[1] = rPtr[1] + pb[1];
        rPtr[2] = rPtr[2] + pb[2];
    }
    *out = rPtr[0] - pos[0];
    out[1] = gObjHitsScalarZero[0];
    out[2] = rPtr[2] - pos[2];
    return 1;
}

int ObjHits_CalcSkeletonResponse3D(f32* pos, f32 radius, GameObject* obj, ObjHitsSkeletonHit* hits,
                                   ModelJointWork* jointPoints, int jointModel, ObjHitsSkeletonHit* bestHit,
                                   f32 t, f32 axial, f32* out) {
    float moveLen;
    float zf;
    int idxA;
    float* pPtr;
    float* aPtr;
    ObjHitsSkeletonHit* saved;
    float* rPtr;
    float* norm;
    float* pb;
    struct {
        float out[9];
        Vec accum;
    } pj;
    float reflect[3];
    float normalOut[3];
    Vec normAccum;
    Vec diff;
    Vec move;
    Vec projPos;

    aPtr = &pj.out[9];
    saved = hits;
    move.x = obj->anim.localPosX - obj->anim.previousLocalPosX;
    move.y = obj->anim.localPosY - obj->anim.previousLocalPosY;
    move.z = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
    moveLen = Vec3_Length(&move.x);
    projPos.x = pos[0];
    projPos.y = pos[1];
    projPos.z = pos[2];
    projPos.x = projPos.x - move.x;
    projPos.y = projPos.y - move.y;
    projPos.z = projPos.z - move.z;
    pj.accum.x = gObjHitsScalarZero[0];
    pj.accum.y = gObjHitsScalarZero[0];
    pj.accum.z = gObjHitsScalarZero[0];
    normAccum.x = gObjHitsScalarZero[0];
    normAccum.y = gObjHitsScalarZero[0];
    normAccum.z = gObjHitsScalarZero[0];
    Vec3_Normalize(ObjHits_CalcTaperedCapsuleNormal(&projPos.x, bestHit->capsuleAxial, bestHit->pointA, bestHit->pointB,
                                                    jointPoints->jointRadii[bestHit->pointIndexA],
                                                    jointPoints->jointRadii[bestHit->pointIndexB],
                                                    jointPoints->jointLengths[bestHit->pointIndexA], normalOut));
    pPtr = pj.out;
    zf = 0.0f;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1) {
        pb = ObjHits_ProjectPointToTaperedCapsule3D(
            &projPos.x, radius, hits->capsuleAxial, hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
            jointPoints->jointRadii[hits->pointIndexB], jointPoints->jointLengths[idxA], pPtr);
        if (axial > zf) {
            hits->inverseDistance = hits->inverseDistance / axial;
        } else {
            hits->inverseDistance = zf;
        }
        pb[0] = pb[0] * hits->inverseDistance;
        pb[1] = pb[1] * hits->inverseDistance;
        pb[2] = pb[2] * hits->inverseDistance;
        pj.accum.x = pj.accum.x + pb[0];
        pj.accum.y = pj.accum.y + pb[1];
        pj.accum.z = pj.accum.z + pb[2];
        norm = ObjHits_CalcTaperedCapsuleNormal(
            pos, hits->capsuleAxial, hits->pointA, hits->pointB, jointPoints->jointRadii[hits->pointIndexA],
            jointPoints->jointRadii[hits->pointIndexB], jointPoints->jointLengths[hits->pointIndexA], normalOut);
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
    if (moveLen > axial) {
        move.x = move.x * (moveLen - axial);
        move.y = move.y * (moveLen - axial);
        move.z = move.z * (moveLen - axial);
        Vec3_ReflectAgainstNormal(&normAccum.x, &move.x, rPtr = reflect);
    } else {
        rPtr = reflect;
        rPtr[0] = gObjHitsScalarZero[0];
        rPtr[1] = gObjHitsScalarZero[0];
        rPtr[2] = gObjHitsScalarZero[0];
    }
    pj.accum.x = pj.accum.x + rPtr[0];
    pj.accum.y = pj.accum.y + rPtr[1];
    pj.accum.z = pj.accum.z + rPtr[2];
    rPtr[0] = gObjHitsScalarZero[0];
    rPtr[1] = gObjHitsScalarZero[0];
    rPtr[2] = gObjHitsScalarZero[0];
    hits = saved;
    for (; (idxA = hits->pointIndexA) != OBJHITS_SKELETON_HIT_SENTINEL; hits = hits + 1) {
        pb = ObjHits_ProjectPointToTaperedCapsule3D(
            aPtr, radius, hits->capsuleAxial, hits->pointA, hits->pointB, jointPoints->jointRadii[idxA],
            jointPoints->jointRadii[hits->pointIndexB], jointPoints->jointLengths[idxA], pPtr);
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

float* ObjHits_ProjectPointToTaperedCapsuleXZ(float* point, float pointRadius, float axial, float* base, float* tip,
                                              float baseRadius, float tipRadius, float length, float* out) {
    float invLength;
    float zero;
    float axisDir[3];
    float surfacePoint[3];

    zero = gObjHitsScalarZero[0];
    if (axial < zero) {
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
    if (axial > length) {
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
    invLength = gObjHitsScalarOne[0] / length;
    axisDir[0] = axisDir[0] * invLength;
    axisDir[1] = axisDir[1] * invLength;
    axisDir[2] = axisDir[2] * invLength;
    Vec3_ScaleAdd(base, axisDir, axial, surfacePoint);
    out[0] = point[0] - surfacePoint[0];
    out[1] = gObjHitsScalarZero[0];
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

float* ObjHits_ProjectPointToTaperedCapsule3D(float* point, float pointRadius, float axial, float* base, float* tip,
                                              float baseRadius, float tipRadius, float length, float* out) {
    float invLength;
    float axisDir[3];
    float surfacePoint[3];

    if (axial < gObjHitsScalarZero[0]) {
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
    if (axial > length) {
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
    invLength = gObjHitsScalarOne[0] / length;
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

float* ObjHits_CalcTaperedCapsuleNormal(float* point, float axial, float* base, float* tip, float baseRadius,
                                        float tipRadius, float length, float* out) {
    float invAxial;
    float radiusDelta;
    float radiusOffset;
    float axisDir[3];
    float normal[3];
    float blended[3];
    float cross[3];
    float surface[3];

    if (axial <= gObjHitsScalarZero[0]) {
        *out = *point - *tip;
        out[1] = point[1] - tip[1];
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        return out;
    }
    if (axial >= length) {
        *out = *point - *tip;
        out[1] = point[1] - tip[1];
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        return out;
    } else {
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
        if (radiusDelta == gObjHitsScalarZero[0]) {
            out[0] = normal[0];
            out[1] = normal[1];
            out[2] = normal[2];
            return out;
        } else {
            axisDir[0] = axisDir[0] * axial;
            axisDir[1] = axisDir[1] * axial;
            axisDir[2] = axisDir[2] * axial;
            Vec3_ScaleAdd(axisDir, normal, radiusOffset, blended);
            Vec3_Normalize(blended);
            axisDir[0] = axisDir[0] * (gObjHitsScalarOne[0] / axial);
            invAxial = gObjHitsScalarOne[0] / axial;
            axisDir[1] = axisDir[1] * invAxial;
            axisDir[2] = axisDir[2] * invAxial;
            Vec3_Cross(normal, axisDir, cross);
            Vec3_Normalize(cross);
            Vec3_Cross(cross, blended, out);
        }
    }
    return out;
}

int ObjHits_TestTaperedCapsuleXZ(float* point, float pointRadius, float baseRadius, float tipRadius, float* base,
                                 float* axis, float* tip, float length, float* axial, float* dist2, float* sumR) {
    float deltaX, deltaZ;
    float radialX, radialZ;
    float tipDeltaX, tipDeltaZ;
    float projection;
    float radiusSum;

    deltaX = point[0] - base[0];
    deltaZ = point[2] - base[2];
    *axial = deltaX * axis[0] + deltaZ * axis[2];
    if (*axial > length) {
        tipDeltaX = (tip[0] - point[0]) * (tip[0] - point[0]);
        tipDeltaZ = (tip[2] - point[2]) * (tip[2] - point[2]);
        *dist2 = tipDeltaX + tipDeltaZ;
        radiusSum = pointRadius + tipRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    if (*axial < gObjHitsScalarZero[0]) {
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

int ObjHits_TestTaperedCapsule3D(float* point, float pointRadius, float baseRadius, float tipRadius, float* base,
                                 float* axis, float* tip, float length, float* axial, float* dist2, float* sumR) {
    float deltaX, deltaY, deltaZ;
    float radialX, radialY, radialZ;
    float tipDeltaX, tipDeltaY, tipDeltaZ;
    float radiusSum;

    deltaX = point[0] - base[0];
    deltaY = point[1] - base[1];
    deltaZ = point[2] - base[2];
    *axial = deltaZ * axis[2] + (deltaX * axis[0] + deltaY * axis[1]);
    if (*axial > length) {
        tipDeltaX = tip[0] - point[0];
        tipDeltaY = tip[1] - point[1];
        tipDeltaZ = tip[2] - point[2];
        *dist2 = tipDeltaZ * tipDeltaZ + (tipDeltaX * tipDeltaX + tipDeltaY * tipDeltaY);
        radiusSum = pointRadius + tipRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    if (*axial < gObjHitsScalarZero[0]) {
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

void ObjHits_SortSweepEntries(ObjHitsSweepEntry** sweepPtrs, int entryCount) {
    int maxGap;
    ObjHitsSweepEntry* prevEntry;
    int index;
    int insertIndex;
    int gap;
    ObjHitsSweepEntry* entry;

    gap = 1;
    maxGap = (entryCount - 1) / 9;
    for (; gap <= maxGap; gap = gap * 3 + 1) {
    }
    for (; gap > 0; gap = gap / 3) {
        for (index = gap + 1; index < entryCount; index++) {
            entry = sweepPtrs[index];
            insertIndex = index;
            while ((insertIndex > gap) && (prevEntry = sweepPtrs[insertIndex - gap], prevEntry->minX > entry->minX)) {
                sweepPtrs[insertIndex] = prevEntry;
                insertIndex -= gap;
            }
            sweepPtrs[insertIndex] = entry;
        }
    }
    return;
}

void ObjHits_TickPriorityHitCooldowns(void) {
    int slotOffset;
    short slotIndex;
    u8* base;
    ObjHitsPriorityWorkSlot* workSlot;

    slotIndex = 0;
    slotOffset = 0;
    do {
        base = (u8*)gObjHitsPriorityHitStates;
        workSlot = (ObjHitsPriorityWorkSlot*)(base + slotOffset);
        if (workSlot->active != 0) {
            workSlot->active--;
        }
        slotOffset = slotOffset + OBJHITS_PRIORITY_WORK_SLOT_SIZE;
        slotIndex++;
    } while (slotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT);
    gObjHitsPriorityHitTickDelta = timeDelta;
    return;
}

void ObjHitbox_UpdateRotatedBounds(ObjHitbox* hitbox, int advanceMatrix) {
    ObjHitboxTransformState* transformState;
    float* matrixBase;
    int matrixFloatOffset;
    MatrixTransform xform;

    transformState = hitbox->transformState;
    if (transformState != 0) {
        if (advanceMatrix != 0) {
            transformState->activeMatrixIndex = (transformState->activeMatrixIndex + 1) & 1;
        }
        matrixFloatOffset = transformState->activeMatrixIndex * OBJHITBOX_STATE_MATRIX_FLOAT_COUNT;
        matrixBase = (float*)transformState->matrices + matrixFloatOffset;
        xform.rotX = -hitbox->rotationX;
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Y) != 0) {
            xform.rotY = 0;
        } else {
            xform.rotY = -hitbox->rotationY;
        }
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Z) != 0) {
            xform.rotZ = 0;
        } else {
            xform.rotZ = -hitbox->rotationZ;
        }
        xform.scale = gObjHitsScalarOne[0];
        xform.x = -hitbox->radiusX;
        xform.y = -hitbox->radiusY;
        xform.z = -hitbox->radiusZ;
        mtxRotateByVec3s(matrixBase, &xform);
        xform.rotX = hitbox->rotationX;
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Y) != 0) {
            xform.rotY = 0;
        } else {
            xform.rotY = hitbox->rotationY;
        }
        if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Z) != 0) {
            xform.rotZ = 0;
        } else {
            xform.rotZ = hitbox->rotationZ;
        }
        xform.scale = gObjHitsScalarOne[0];
        xform.x = hitbox->radiusX;
        xform.y = hitbox->radiusY;
        xform.z = hitbox->radiusZ;
        matrixFloatOffset = (transformState->activeMatrixIndex + 2) * OBJHITBOX_STATE_MATRIX_FLOAT_COUNT;
        setMatrixFromObjectPos((float*)transformState->matrices + matrixFloatOffset, &xform);
        if (transformState->resetFrames != 0) {
            transformState->resetFrames--;
        }
    }
    return;
}

int ObjHits_CheckHitVolumes(GameObject* objA, GameObject* objB, GameObject* srcObj, char checkA, char checkB, u32 mask, u32 volMask) {
    ObjHitsContactScratchEntry* contact;
    int countA;
    int countB;
    ObjHitsPriorityState* stateA;
    int idxA;
    ObjHitsContactScratchEntry* cw;
    char modeB;
    float* sphB;
    float* curSphA;
    float* curDefA;
    float* spheresA;
    float* spheresB;
    float* defA;
    ModelHitSphereDef* volA;
    ModelHitSphereDef* volB;
    ObjHitsPriorityState* stateSrc;
    s64 volBits;
    ObjHitsContactScratchEntry* contactBase;
    int count;
    char modeA;
    char miss;
    s64 maskB;
    ModelHitSphereDef* vol;
    float* pb2;
    ObjModel* modelBank;
    ModelFileHeader* modelFile;
    s64 maskA;
    ObjHitsContactScratchEntry* cr;
    int result;
    s64 bitA;
    s64 bitB;
    int i;
    int j;
    int k;
    int hit;
    ObjHitsPriorityState* stateB;
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
    float minA;
    float maxA;
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
    float lo;
    float hi;
    float blo;
    float bhi;
    float cc;
    float sb0;
    float disc;
    float q;
    float sc;
    float bestX;
    float bestZ;
    float bestDepth;
    float invLenSq;
    float defs[8];
    float sphs[8];
    u8 volB0[24];
    u8 volA0[24];

    result = 0;
    stateA = (ObjHitsPriorityState*)(&objA->anim)->hitReactState;
    stateB = (ObjHitsPriorityState*)(&objB->anim)->hitReactState;
    stateSrc = (ObjHitsPriorityState*)(&srcObj->anim)->hitReactState;
    if ((stateSrc->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) &&
        (*(s8*)&stateSrc->resetHitboxMode != 0 || stateSrc->activeHitboxMode != 0)) {
        return 0;
    }
    if ((stateB->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) &&
        (*(s8*)&stateB->resetHitboxMode != 0 || stateB->activeHitboxMode != 0)) {
        return 0;
    }
    modeA = 0;
    modeB = 0;
    if ((checkA != 0 && (stateA->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) != 0) ||
        (checkB != 0 && stateA->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES)) {
        modelBank = ObjHits_GetActiveModel(objA);
        modelFile = modelBank->file;
        countA = modelFile->hitVolumeCount;
        spheresA = (f32*)modelBank->activeHitVolumeSpheres;
        defA = (f32*)modelBank->hitVolumeSphereBuffers[((modelBank->bufferFlags >> 2) & 1) ^ 1];
        volA = (ModelHitSphereDef*)modelFile->hitVolumes;
        if (srcObj != objA) {
            radiusA = stateSrc->secondaryRadiusXZ;
        } else {
            radiusA = stateA->secondaryRadiusXZ;
        }
        if ((objA->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
            return 0;
        }
    } else {
        countA = 1;
        spheresA = sphs;
        defA = defs;
        volA = (ModelHitSphereDef*)volA0;
        if (stateA->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) {
            modeA = 1;
        }
        radiusA = stateA->secondaryRadius;
        sphs[0] = radiusA;
        sphs[1] = objA->anim.worldPosX - playerMapOffsetX;
        sphs[2] = objA->anim.worldPosY;
        sphs[3] = objA->anim.worldPosZ - playerMapOffsetZ;
        defs[0] = radiusA;
        defs[1] = stateA->worldPosX - playerMapOffsetX;
        defs[2] = stateA->worldPosY;
        defs[3] = stateA->worldPosZ - playerMapOffsetZ;
        volA->sphereIndex = 0;
        volA->maskBit = 0;
        volA->linkedSpheres = 0;
    }
    if ((checkA != 0 && (stateB->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) != 0) ||
        (checkB != 0 && stateB->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES)) {
        modelBank = ObjHits_GetActiveModel(objB);
        modelFile = modelBank->file;
        countB = modelFile->hitVolumeCount;
        spheresB = (f32*)modelBank->activeHitVolumeSpheres;
        volB = (ModelHitSphereDef*)modelFile->hitVolumes;
        radiusB = stateB->secondaryRadiusXZ;
        if ((objB->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
            return 0;
        }
    } else {
        countB = 1;
        spheresB = &sphs[4];
        volB = (ModelHitSphereDef*)volB0;
        if (stateB->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) {
            modeB = 1;
        }
        radiusB = stateB->secondaryRadius;
        sphs[4] = radiusB;
        sphs[5] = objB->anim.worldPosX - playerMapOffsetX;
        sphs[6] = objB->anim.worldPosY;
        sphs[7] = objB->anim.worldPosZ - playerMapOffsetZ;
        defs[4] = sphs[0];
        defs[5] = stateA->worldPosX - playerMapOffsetX;
        defs[6] = stateA->worldPosY;
        defs[7] = stateA->worldPosZ - playerMapOffsetZ;
        volB->sphereIndex = 0;
        volB->maskBit = 0;
        volB->linkedSpheres = 0;
    }
    if (countA > 64 || countB > 64) {
        debugPrintf(sObjHitsTooManyHitSpheresWarning);
    }
    dxs = objA->anim.worldPosX - objB->anim.worldPosX;
    dys = objA->anim.worldPosY - objB->anim.worldPosY;
    dzs = objA->anim.worldPosZ - objB->anim.worldPosZ;
    dsq = sqrtf(dzs * dzs + (dxs * dxs + (dys * dys)));
    if (dsq > 100.0f + (radiusA + radiusB)) {
        return 0;
    }
    maskA = 0;
    maskB = 0;
    volBits = 0;
    i = 0;
    vol = volA;
    for (; i < countA; i++) {
        if (i == vol->sphereIndex) {
            if ((mask & 1 << vol->maskBit) != 0) {
                maskA |= 1 << i;
            }
            if ((volMask & 1 << vol->maskBit) != 0) {
                volBits |= 1 << i;
            }
        }
        vol++;
    }
    j = 0;
    vol = volB;
    for (; j < countB; j++) {
        if (j == vol->sphereIndex) {
            maskB |= 1 << j;
        }
        vol++;
    }
    contactBase = gObjHitsContactScratch;
    bestDepth = -1.0f;
    count = 1;
    while (count != 0) {
        count = 0;
        i = 0;
        curSphA = spheresA;
        curDefA = defA;
        contact = contactBase;
        for (; i < countA; i++) {
            bitA = 1 << i;
            if ((maskA & bitA) != 0) {
                radA2 = curSphA[0];
                xA = curSphA[1];
                yA = curSphA[2];
                zA = curSphA[3];
                miss = 1;
                if ((volBits & bitA) != 0) {
                    miss = 0;
                }
                if (miss == 0) {
                    dax = curDefA[1];
                    day = curDefA[2];
                    daz = curDefA[3];
                    ax = xA - dax;
                    ay = yA - day;
                    az = zA - daz;
                    lenSq = az * az + (ax * ax + (ay * ay));
                    if (lenSq > gObjHitsScalarZero[0]) {
                        invLenSq = gObjHitsScalarOne[0] / lenSq;
                    } else {
                        miss = 1;
                    }
                }
                j = 0;
                sphB = spheresB;
                cw = contact;
                minA = yA - radA2;
                maxA = yA + radA2;
                for (; j < countB; j++) {
                    bitB = 1 << j;
                    if ((maskB & bitB) != 0) {
                        hit = 0;
                        if ((i == 0 && modeA != 0) || (j == 0 && modeB != 0)) {
                            if (modeA != 0) {
                                lo = yA + stateA->secondaryCapsuleOffsetA;
                                hi = yA + stateA->secondaryCapsuleOffsetB;
                                blo = sphB[2] - sphB[0];
                                bhi = sphB[2] + sphB[0];
                            } else {
                                lo = minA;
                                hi = maxA;
                                blo = stateB->secondaryCapsuleOffsetA + sphB[2];
                                bhi = stateB->secondaryCapsuleOffsetB + sphB[2];
                            }
                            if ((!(blo < lo) || !(bhi < lo)) && (!(blo > hi) || !(bhi > hi))) {
                                sumSq = radA2 + sphB[0];
                                sumSq = sumSq * sumSq;
                                dxs = xA - sphB[1];
                                dsq = dxs * dxs;
                                if (dsq < sumSq) {
                                    dzs = zA - sphB[3];
                                    dsq = dzs * dzs + dsq;
                                    if (dsq < sumSq) {
                                        dys = gObjHitsScalarZero[0];
                                        hit = 1;
                                    }
                                }
                            }
                        } else {
                            sumSq = (radA2 + sphB[0]) * (radA2 + sphB[0]);
                            if (miss != 0) {
                                dxs = xA - sphB[1];
                                dsq = dxs * dxs;
                                if (dsq < sumSq) {
                                    dys = yA - sphB[2];
                                    dsq = dys * dys + dsq;
                                    if (dsq < sumSq) {
                                        dzs = zA - sphB[3];
                                        dsq = dzs * dzs + dsq;
                                        if (dsq < sumSq) {
                                            hit = 1;
                                        }
                                    }
                                }
                            } else {
                                cx = dax - sphB[1];
                                cy = day - sphB[2];
                                cz = daz - sphB[3];
                                cc = (cz * cz + (cx * cx + (cy * cy))) - sumSq;
                                bb = cz * az + (cx * ax + (cy * ay));
                                if (!(bb > gObjHitsScalarZero[0]) || !(cc > gObjHitsScalarZero[0])) {
                                    disc = bb * bb - lenSq * cc;
                                    if (disc >= *(f32*)&gObjHitsScalarZero[0]) {
                                        q = lenSq + bb;
                                        if (q >= *(f32*)&gObjHitsScalarZero[0] || q * q <= disc) {
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
                        if (hit != 0 && count < 64) {
                            if (checkB != 0) {
                                if (dsq > gObjHitsScalarZero[0]) {
                                    bb = sqrtf(sumSq);
                                    dsq = sqrtf(dsq);
                                    if (bb > gObjHitsScalarZero[0]) {
                                        sumSq = (bb - dsq) / bb;
                                    } else {
                                        sumSq = gObjHitsScalarZero[0];
                                    }
                                    cw->depth = sumSq;
                                    cw->responseX = dxs * sumSq;
                                    cw->responseZ = dzs * sumSq;
                                }
                            } else {
                                sumSq = sqrtf(dzs * dzs + (dxs * dxs + (dys * dys)));
                                if (sumSq > gObjHitsScalarZero[0]) {
                                    dxs = dxs / sumSq;
                                    dys = dys / sumSq;
                                    dzs = dzs / sumSq;
                                }
                                sb0 = sphB[0];
                                cw->contactOffsetX = dxs * sb0;
                                cw->contactOffsetY = dys * sb0;
                                cw->contactOffsetZ = dzs * sb0;
                            }
                            cw->sphereIndexA = i;
                            cw->sphereIndexB = j;
                            cw++;
                            contact++;
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
        for (; k < count; k++) {
            idxA = cr->sphereIndexA;
            hit = cr->sphereIndexB;
            linkA = volA[idxA].linkedSpheres;
            linkB = volB[hit].linkedSpheres;
            link = linkA;
            while (link != 0) {
                maskA |= 1 << (idxA + (u16)((link & 0xf000) >> 12));
                link = link << 4;
            }
            link = linkB;
            while (link != 0) {
                maskB |= 1 << (hit + (u16)((link & 0xf000) >> 12));
                link = link << 4;
            }
            if (linkA == 0 && linkB == 0) {
                if (checkA != 0) {
                    pb2 = &spheresB[hit * 4];
                    cx = pb2[1] + cr->contactOffsetX;
                    ObjHits_RecordPositionHit(objB, objA, stateSrc->hitVolumePriority,
                                              (u8)stateSrc->hitVolumeId, hit, cx,
                                              (modeB != 0) ? spheresA[idxA * 4 + 2] : pb2[2] + cr->contactOffsetY,
                                              pb2[3] + cr->contactOffsetZ);
                    result = 1;
                } else if (checkB != 0) {
                    if (cr->depth > bestDepth) {
                        bestDepth = cr->depth;
                        bestX = cr->responseX;
                        bestZ = cr->responseZ;
                    }
                }
            } else if (linkA == 0) {
                maskA |= 1 << idxA;
            } else if (linkB == 0) {
                maskB |= 1 << hit;
            }
            cr++;
        }
    }
    if (checkA != 0 && result != 0) {
        if ((stateA->flags & 0x80) != 0) {
            react = ObjAnim_GetPriorityHitState(&objA->anim);
            if (react != 0) {
                react->flags = react->flags & ~OBJHITS_PRIORITY_STATE_ENABLED;
            }
        }
        if ((stateB->flags & 0x80) != 0) {
            react = ObjAnim_GetPriorityHitState(&objB->anim);
            if (react != 0) {
                react->flags = react->flags & ~OBJHITS_PRIORITY_STATE_ENABLED;
            }
        }
        return 1;
    }
    if (checkB != 0) {
        if (bestDepth > gObjHitsScalarZero[0]) {
            if (objA == srcObj) {
                ObjHits_RecordObjectHit(objB, objA, stateSrc->objectPairPriority,
                                        stateSrc->objectPairHitVolume, hit);
                ObjHits_RecordObjectHit(objA, objB, stateB->objectPairPriority,
                                        stateB->objectPairHitVolume, idxA);
                ObjHits_ApplyPairResponse(objA, objB, -bestX, gObjHitsScalarZero[0], -bestZ, 0);
                return 1;
            }
        }
    }
    return 0;
}

void ObjHits_OnPlayerHitVolumeMiss(GameObject* objA, GameObject* objB, GameObject* attachment, void* state, void* attachmentState, f32 dt) {
}

void ObjHits_CheckObjectHitVolumes(GameObject* objA, GameObject* objB, GameObject* attA, GameObject* attB, f32 dt) {
    ObjHitsPriorityState* attStateB;
    ObjHitsPriorityState* stateB;
    ObjHitsPriorityState* attStateA;
    ObjHitsPriorityState* stateA;
    ObjModel* hitboxBuf;
    u32 bufIndex;
    u32 mask;
    u8 result;
    stateB = (ObjHitsPriorityState*)objB->anim.hitReactState;
    stateA = (ObjHitsPriorityState*)objA->anim.hitReactState;
    if (attA != NULL) {
        attStateA = ObjAnim_GetPriorityHitState(&attA->anim);
    } else {
        attStateA = NULL;
    }
    if (attB != NULL) {
        attStateB = ObjAnim_GetPriorityHitState(&attB->anim);
    } else {
        attStateB = NULL;
    }
    result = 0;
    if ((stateA->objectHitMask != 0) && (stateA->suppressOutgoingHits == 0)) {
        if (objA->anim.classId == 1) {
            hitboxBuf = ObjHits_GetActiveModel(objA);
            bufIndex = (hitboxBuf->bufferFlags >> 2) & 1;
            if ((stateA->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0) {
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsPrimaryHitboxBufferScratch0,
                       hitboxBuf->file->hitVolumeCount << 4);
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1], gObjHitsPrimaryHitboxBufferScratch1,
                       hitboxBuf->file->hitVolumeCount << 4);
            } else {
                memcpy(gObjHitsPrimaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                       hitboxBuf->file->hitVolumeCount << 4);
                memcpy(gObjHitsPrimaryHitboxBufferScratch1, hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                       hitboxBuf->file->hitVolumeCount << 4);
            }
            if (attA != NULL) {
                hitboxBuf = ObjHits_GetActiveModel(attA);
                bufIndex = (hitboxBuf->bufferFlags >> 2) & 1;
                if ((stateA->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0) {
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsSecondaryHitboxBufferScratch0,
                           hitboxBuf->file->hitVolumeCount << 4);
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1], gObjHitsSecondaryHitboxBufferScratch1,
                           hitboxBuf->file->hitVolumeCount << 4);
                } else {
                    memcpy(gObjHitsSecondaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                           hitboxBuf->file->hitVolumeCount << 4);
                    memcpy(gObjHitsSecondaryHitboxBufferScratch1, hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                           hitboxBuf->file->hitVolumeCount << 4);
                    stateA->flags = stateA->flags | OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED;
                }
            }
        }
        mask = stateA->objectHitMask >> 4;
        if (mask != 0) {
            result = ObjHits_CheckHitVolumes(objA, objB, objA, 1, 0, mask, stateA->skeletonHitMask >> 4);
        }
        if (((attA != NULL) && (result == 0)) && (mask = stateA->objectHitMask & 0xf, mask != 0)) {
            result = ObjHits_CheckHitVolumes(attA, objB, objA, 1, 0, mask, stateA->skeletonHitMask & 0xf);
        }
        if ((result == 0) && (objA->anim.classId == 1)) {
            ObjHits_OnPlayerHitVolumeMiss(objA, objB, attA, stateA, attStateA, dt);
        }
    }
    result = 0;
    if (((stateB->sourceMask & 0x80) == 0) && (stateB->objectHitMask != 0) && (stateB->suppressOutgoingHits == 0)) {
        if (objB->anim.classId == 1) {
            hitboxBuf = ObjHits_GetActiveModel(objB);
            bufIndex = (hitboxBuf->bufferFlags >> 2) & 1;
            if ((stateB->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0) {
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsPrimaryHitboxBufferScratch0,
                       hitboxBuf->file->hitVolumeCount << 4);
                memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1], gObjHitsPrimaryHitboxBufferScratch1,
                       hitboxBuf->file->hitVolumeCount << 4);
            } else {
                memcpy(gObjHitsPrimaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                       hitboxBuf->file->hitVolumeCount << 4);
                memcpy(gObjHitsPrimaryHitboxBufferScratch1, hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                       hitboxBuf->file->hitVolumeCount << 4);
            }
            if (attB != NULL) {
                hitboxBuf = ObjHits_GetActiveModel(attB);
                bufIndex = (hitboxBuf->bufferFlags >> 2) & 1;
                if ((stateB->flags & OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED) != 0) {
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex], gObjHitsSecondaryHitboxBufferScratch0,
                           hitboxBuf->file->hitVolumeCount << 4);
                    memcpy(hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1], gObjHitsSecondaryHitboxBufferScratch1,
                           hitboxBuf->file->hitVolumeCount << 4);
                } else {
                    memcpy(gObjHitsSecondaryHitboxBufferScratch0, hitboxBuf->hitVolumeSphereBuffers[bufIndex],
                           hitboxBuf->file->hitVolumeCount << 4);
                    memcpy(gObjHitsSecondaryHitboxBufferScratch1, hitboxBuf->hitVolumeSphereBuffers[bufIndex ^ 1],
                           hitboxBuf->file->hitVolumeCount << 4);
                    stateB->flags = stateB->flags | OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED;
                }
            }
        }
        mask = stateB->objectHitMask >> 4;
        if (mask != 0) {
            result = ObjHits_CheckHitVolumes(objB, objA, objB, 1, 0, mask, stateB->skeletonHitMask >> 4);
        }
        if (((attB != NULL) && (result == 0)) && (mask = stateB->objectHitMask & 0xf, mask != 0)) {
            result = ObjHits_CheckHitVolumes(attB, objA, objB, 1, 0, mask, stateB->skeletonHitMask & 0xf);
        }
        if ((result == 0) && (objB->anim.classId == 1)) {
            ObjHits_OnPlayerHitVolumeMiss(objB, objA, attB, stateB, attStateB, dt);
        }
    }
}
void ObjHits_RegisterActiveHitVolumeObject(GameObject* obj) {
    int index;

    index = 0;
    while (index < OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT && gObjHitsActiveHitVolumeObjects[index] != NULL) {
        index = index + 1;
    }
    if (index == OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT) {
        gObjHitsActiveHitVolumeObjects[0] = obj;
        return;
    }
    gObjHitsActiveHitVolumeObjects[index] = obj;
    return;
}

void ObjHits_ApplyPairResponse(GameObject* objA, GameObject* objB, f32 x, f32 y, f32 z, int flag) {
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
    f32 cosVal;
    f32 cosSq;
    f32 weightA;
    f32 weightB;
    f32 sum;
    f32 blend;
    f32 invBlend;

    ObjContact_DispatchCallbacks(objA, objB);
    animA = &objA->anim;
    animB = &objB->anim;
    stateA = (ObjHitsPriorityState*)animA->hitReactState;
    stateB = (ObjHitsPriorityState*)animB->hitReactState;
    stateA->flags = stateA->flags | 8;
    stateB->flags = stateB->flags | 8;
    *(GameObject**)stateA = objB;
    *(GameObject**)stateB = objA;
    if (animA->parent != NULL) {
        Obj_TransformWorldVectorToLocal(x, y, z, &localAx, &localAy, &localAz, animA->parent);
    } else {
        localAx = x;
        localAy = y;
        localAz = z;
    }
    if (animB->parent != NULL) {
        Obj_TransformWorldVectorToLocal(x, y, z, &localBx, &localBy, &localBz, animB->parent);
    } else {
        localBx = x;
        localBy = y;
        localBz = z;
    }
    if ((animA->classId == 1) && (stateA->lateralResponseWeight != 0) &&
        ((stateB->flags & OBJHITS_PRIORITY_STATE_IMMOVABLE) == 0)) {
        animA->localPosX = animA->localPosX - localAx;
        animA->localPosY = animA->localPosY - localAy;
        animA->localPosZ = animA->localPosZ - localAz;
        if (flag != 0) {
            animA->worldPosX = animA->worldPosX - x;
            animA->worldPosY = animA->worldPosY - y;
            animA->worldPosZ = animA->worldPosZ - z;
        } else {
            Obj_TransformLocalPointToWorld(animA->localPosX, animA->localPosY, animA->localPosZ, &animA->worldPosX,
                                           &animA->worldPosY, &animA->worldPosZ, animA->parent);
        }
    } else if ((animB->classId == 1) && (stateB->lateralResponseWeight != 0) &&
               ((stateA->flags & OBJHITS_PRIORITY_STATE_IMMOVABLE) == 0)) {
        animB->localPosX = animB->localPosX + localBx;
        animB->localPosY = animB->localPosY + localBy;
        animB->localPosZ = animB->localPosZ + localBz;
        if (flag != 0) {
            animB->worldPosX = animB->worldPosX + x;
            animB->worldPosY = animB->worldPosY + y;
            animB->worldPosZ = animB->worldPosZ + z;
        } else {
            Obj_TransformLocalPointToWorld(animB->localPosX, animB->localPosY, animB->localPosZ, &animB->worldPosX,
                                           &animB->worldPosY, &animB->worldPosZ, animB->parent);
        }
    } else if (stateB->lateralResponseWeight == 0) {
        if (stateA->lateralResponseWeight != 0) {
            animA->localPosX = animA->localPosX - localAx;
            animA->localPosY = animA->localPosY - localAy;
            animA->localPosZ = animA->localPosZ - localAz;
            if (flag != 0) {
                animA->worldPosX = animA->worldPosX - x;
                animA->worldPosY = animA->worldPosY - y;
                animA->worldPosZ = animA->worldPosZ - z;
            } else {
                Obj_TransformLocalPointToWorld(animA->localPosX, animA->localPosY, animA->localPosZ, &animA->worldPosX,
                                               &animA->worldPosY, &animA->worldPosZ, animA->parent);
            }
        }
    } else if (stateA->lateralResponseWeight == 0) {
        if (stateB->lateralResponseWeight != 0) {
            animB->localPosX = animB->localPosX + localBx;
            animB->localPosY = animB->localPosY + localBy;
            animB->localPosZ = animB->localPosZ + localBz;
            if (flag != 0) {
                animB->worldPosX = animB->worldPosX + x;
                animB->worldPosY = animB->worldPosY + y;
                animB->worldPosZ = animB->worldPosZ + z;
            } else {
                Obj_TransformLocalPointToWorld(animB->localPosX, animB->localPosY, animB->localPosZ, &animB->worldPosX,
                                               &animB->worldPosY, &animB->worldPosZ, animB->parent);
            }
        }
    } else {
        angle = getAngle(-x, -z) & 0xffff;
        angleA = animA->rotX - angle;
        if (angleA > 0x8000) {
            angleA -= 0xffff;
        }
        if (angleA < -0x8000) {
            angleA += 0xffff;
        }
        angleB = animB->rotX - (int)((angle + 0x8000) & 0xffff);
        if (angleB > 0x8000) {
            angleB -= 0xffff;
        }
        if (angleB < -0x8000) {
            angleB += 0xffff;
        }
        cosVal = mathCosf((3.1415927f * angleA) / 32768.0f);
        cosSq = cosVal * cosVal;
        weightA = stateA->lateralResponseWeight * cosSq + stateA->axialResponseWeight * (gObjHitsScalarOne[0] - cosSq);
        cosVal = mathCosf((3.1415927f * angleB) / 32768.0f);
        cosSq = cosVal * cosVal;
        weightB = stateB->lateralResponseWeight * cosSq + stateB->axialResponseWeight * (gObjHitsScalarOne[0] - cosSq);
        if (weightA < weightB * gObjHitsResponseDominanceRatio) {
            weightA = gObjHitsScalarZero[0];
        } else if (weightB < weightA * gObjHitsResponseDominanceRatio) {
            weightB = gObjHitsScalarZero[0];
        }
        sum = weightA + weightB;
        if (sum > gObjHitsScalarZero[0]) {
            blend = weightB / sum;
        } else {
            blend = gObjHitsScalarZero[0];
        }
        animA->localPosX = animA->localPosX - localAx * blend;
        animA->localPosY = animA->localPosY - localAy * blend;
        animA->localPosZ = animA->localPosZ - localAz * blend;
        Obj_TransformLocalPointToWorld(animA->localPosX, animA->localPosY, animA->localPosZ, &animA->worldPosX,
                                       &animA->worldPosY, &animA->worldPosZ, animA->parent);
        invBlend = gObjHitsScalarOne[0] - blend;
        animB->localPosX = localBx * invBlend + animB->localPosX;
        animB->localPosY = localBy * invBlend + animB->localPosY;
        animB->localPosZ = localBz * invBlend + animB->localPosZ;
        Obj_TransformLocalPointToWorld(animB->localPosX, animB->localPosY, animB->localPosZ, &animB->worldPosX,
                                       &animB->worldPosY, &animB->worldPosZ, animB->parent);
    }
}

void ObjHits_DetectObjectPair(GameObject* objA, GameObject* objB) {
    ObjHitsPriorityState* stateA;
    f32 cy;
    f32 cz;
    int distInt;
    f32 segSq;
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
    ObjHitsPriorityState* stateB;
    f32 sx;
    char vertical;
    int distClamped;
    f32 cx;
    f32 sy;
    f32 sz;

    stateA = (ObjHitsPriorityState*)objA->anim.hitReactState;
    stateB = (ObjHitsPriorityState*)objB->anim.hitReactState;
    if (stateA->activeHitboxMode != 0 || stateB->activeHitboxMode != 0) {
        return;
    }
    dx = objB->anim.worldPosX - objA->anim.worldPosX;
    yB = objB->anim.worldPosY;
    yA = objA->anim.worldPosY;
    dy = yB - yA;
    dz = objB->anim.worldPosZ - objA->anim.worldPosZ;
    radiusA = stateA->primaryRadius;
    radiusB = stateB->primaryRadius;
    vertical = 0;
    if (((stateB->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0) ||
        ((stateA->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0)) {
        if (dy > *(f32*)&gObjHitsScalarZero[0]) {
            if ((stateA->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0) {
                yA = yA + stateA->primaryCapsuleOffsetB;
            } else {
                yA = yA + radiusA;
            }
            if ((stateB->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0) {
                tmp = yB + stateB->primaryCapsuleOffsetA;
            } else {
                tmp = yB - radiusB;
            }
            if (tmp > yA) {
                return;
            }
        } else {
            if ((stateB->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0) {
                yB = yB + stateB->primaryCapsuleOffsetB;
            } else {
                yB = yB + radiusB;
            }
            if ((stateA->shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0) {
                tmp = yA + stateA->primaryCapsuleOffsetA;
            } else {
                tmp = yA - radiusA;
            }
            if (tmp > yB) {
                return;
            }
        }
        dy = gObjHitsScalarZero[0];
        vertical = 1;
    }
    dist = dx * dx + dy * dy + dz * dz;
    if (dist != gObjHitsScalarZero[0]) {
        dist = sqrtf(dist);
    }
    distInt = (int)(f32)(int)dist;
    distClamped = distInt;
    if (distInt > 0x400) {
        distClamped = 0x400;
    }
    if (distClamped <= stateA->capsuleScale) {
        stateA->capsuleScale = distClamped;
    }
    if (distInt > 0x400) {
        distInt = 0x400;
    }
    if (distInt <= stateB->capsuleScale) {
        stateB->capsuleScale = distInt;
    }
    if ((stateB->flags & OBJHITS_PRIORITY_STATE_ENABLED) != 0) {
        sumRadius = radiusB + radiusA;
        sx = objA->anim.worldPosX - stateA->worldPosX;
        sy = objA->anim.worldPosY - stateA->worldPosY;
        sz = objA->anim.worldPosZ - stateA->worldPosZ;
        if (vertical != 0) {
            sy = gObjHitsScalarZero[0];
        }
        segSq = sx * sx + sy * sy + sz * sz;
        if (segSq > gObjHitsScalarOne[0]) {
            cx = objB->anim.worldPosX - stateA->worldPosX;
            cz = objB->anim.worldPosZ - stateA->worldPosZ;
            cy = objB->anim.worldPosY - stateA->worldPosY;
            segSq = (sx * cx + sy * cy + sz * cz) / segSq;
            if ((segSq >= gObjHitsScalarZero[0]) && (segSq <= gObjHitsScalarOne[0])) {
                f32 oz;
                f32 ox;
                f32 oy;

                tmp = (segSq * sz + stateA->worldPosZ) - objB->anim.worldPosZ;
                oz = tmp * tmp;
                tmp = (segSq * sx + stateA->worldPosX) - objB->anim.worldPosX;
                ox = tmp * tmp;
                tmp = (segSq * sy + stateA->worldPosY) - objB->anim.worldPosY;
                oy = tmp * tmp;
                dist = sqrtf(oz + (ox + oy));
            }
        }
        if ((dist < sumRadius) && (dist > gObjHitsScalarZero[0])) {
            ObjHits_RecordObjectHit(objB, objA, stateA->objectPairPriority,
                                    stateA->objectPairHitVolume, 0);
            ObjHits_RecordObjectHit(objA, objB, stateB->objectPairPriority,
                                    stateB->objectPairHitVolume, 0);
            if (((stateB->flags & OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE) == 0) &&
                ((stateA->flags & OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE) == 0)) {
                nx = stateB->worldPosX - stateA->worldPosX;
                ny = stateB->worldPosY - stateA->worldPosY;
                nz = stateB->worldPosZ - stateA->worldPosZ;
                if (vertical != 0) {
                    ny = gObjHitsScalarZero[0];
                }
                tmp = sqrtf(nx * nx + ny * ny + nz * nz);
                if (tmp > gObjHitsScalarZero[0]) {
                    dx = nx / tmp;
                    dy = ny / tmp;
                    dz = nz / tmp;
                } else {
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
}

void ObjHits_CheckSkeletonPair(GameObject* objA, GameObject* objB, void* hits, void* scratchB, void* scratchC, void* scratchD,
                               void* scratchE, int depth) {
    int* hitboxBuf;
    f32 outAxial;
    ObjHitsPriorityState* objAState;
    u8 shapeFlags;
    int hitCount;
    f32 ratio;
    f32 responseX;
    f32 responseY;
    f32 responseZ;
    ObjHitsSkeletonHit* bestHit;
    ObjHitsPriorityState* objBState;
    Vec point;
    f32 response[3];
    Vec point3D;
    Vec pointXZ;

    objBState = (ObjHitsPriorityState*)objB->anim.hitReactState;
    objAState = (ObjHitsPriorityState*)objA->anim.hitReactState;
    if (*(s8*)&objAState->resetHitboxMode != 0 || *(s8*)&objBState->resetHitboxMode != 0 ||
        objBState->activeHitboxMode != 0 || objAState->activeHitboxMode != 0) {
        return;
    }
    hitboxBuf = (int*)ObjHits_GetActiveModel(objA);
    shapeFlags = objBState->shapeFlags;
    if ((shapeFlags & OBJHITBOX_SHAPE_SKELETON_3D) != 0) {
        point.x = objB->anim.worldPosX - playerMapOffsetX;
        point.y = objB->anim.worldPosY;
        point.z = objB->anim.worldPosZ - playerMapOffsetZ;
        point3D = point;
        hitCount =
            ObjHits_CollectSkeletonHits3D(&point3D.x, objBState->primaryRadius, (ModelJointWork*)hitboxBuf[5],
                                          hitboxBuf, (ObjHitsSkeletonHit*)hits, &bestHit, &outAxial);
        if (hitCount != 0) {
            ratio = (objB->anim.hitboxScale * objB->anim.rootMotionScale) /
                    (objA->anim.hitboxScale * objA->anim.rootMotionScale);

            {
                f32* pos = &point.x;
                f32 rad = objBState->primaryRadius;
                u32 ob = (u32)objB;
                ObjHitsSkeletonHit* hh = (ObjHitsSkeletonHit*)hits;
                ModelJointWork* jd = (ModelJointWork*)hitboxBuf[5];
                int mf = *hitboxBuf;
                ObjHitsSkeletonHit* bh = bestHit;
                ObjHits_CalcSkeletonResponse3D(pos, rad, (GameObject*)ob, hh, jd, mf, bh,
                                               (ratio < gObjHitsScalarZero[0])
                                                   ? gObjHitsScalarZero[0]
                                                   : ((ratio > gObjHitsScalarOne[0]) ? gObjHitsScalarOne[0] : ratio),
                                               outAxial, response);
            }
            response[0] = ((responseX = response[0]) < -10.0f) ? -10.0f : ((responseX > 10.0f) ? 10.0f : responseX);
            responseY = response[1];
            response[1] = (responseY < -10.0f) ? -10.0f : ((responseY > 10.0f) ? 10.0f : responseY);
            responseZ = response[2];
            response[2] = (responseZ < -10.0f) ? -10.0f : ((responseZ > 10.0f) ? 10.0f : responseZ);
            ObjHits_ApplyPairResponse(objA, objB, response[0], response[1], (f32)(f64)response[2], 0);
        }
    } else if ((shapeFlags & OBJHITBOX_SHAPE_VERTICAL_SPAN) != 0) {
        point.x = objB->anim.worldPosX - playerMapOffsetX;
        point.y = objB->anim.worldPosY;
        point.z = objB->anim.worldPosZ - playerMapOffsetZ;
        pointXZ = point;
        hitCount = ObjHits_CollectSkeletonHitsXZ(
            &pointXZ.x, objBState->primaryRadius, (ModelJointWork*)hitboxBuf[5], hitboxBuf,
            (ObjHitsSkeletonHit*)hits, &bestHit, point.y + objBState->primaryCapsuleOffsetB,
            point.y + objBState->primaryCapsuleOffsetA, &outAxial);
        if (hitCount != 0) {
            ratio = (objB->anim.hitboxScale * objB->anim.rootMotionScale) /
                    (objA->anim.hitboxScale * objB->anim.rootMotionScale);

            {
                f32* pos = &point.x;
                f32 rad = objBState->primaryRadius;
                u32 ob = (u32)objB;
                ObjHitsSkeletonHit* hh = (ObjHitsSkeletonHit*)hits;
                ModelJointWork* jd = (ModelJointWork*)hitboxBuf[5];
                int mf = *hitboxBuf;
                ObjHitsSkeletonHit* bh = bestHit;
                ObjHits_CalcSkeletonResponseXZ(pos, rad, (GameObject*)ob, hh, jd, mf, bh,
                                               (ratio < gObjHitsScalarZero[0])
                                                   ? gObjHitsScalarZero[0]
                                                   : ((ratio > gObjHitsScalarOne[0]) ? gObjHitsScalarOne[0] : ratio),
                                               outAxial, response);
            }
            response[0] = ((responseX = response[0]) < -10.0f) ? -10.0f : ((responseX > 10.0f) ? 10.0f : responseX);
            responseY = response[1];
            response[1] = (responseY < -10.0f) ? -10.0f : ((responseY > 10.0f) ? 10.0f : responseY);
            responseZ = response[2];
            response[2] = (responseZ < -10.0f) ? -10.0f : ((responseZ > 10.0f) ? 10.0f : responseZ);
            ObjHits_ApplyPairResponse(objA, objB, response[0], response[1], (f32)(f64)response[2], 0);
        }
    } else if (((shapeFlags & OBJHITS_SHAPE_SKELETON) != 0) && (depth < 1)) {
        ObjHits_CheckSkeletonPair(objB, objA, hits, scratchB, scratchC, scratchD, scratchE, depth + 1);
    }
}

void ObjHits_CheckTrackContact(GameObject* objA, GameObject* objB) {
    u32 sphereIdx;
    int mask2;
    u8 contact;
    ObjHitsPriorityState* stateA;
    u32 bits;
    ObjModel* modelBank;
    int i;
    ModelFileHeader* modelFile;
    ModelHitSphereDef* hitVolumes;
    float* curSpheres;
    int prevSpheres;
    ObjHitsPriorityState* stateB;
    int pointCount;
    TrackQueryBounds bounds;
    TrackHitResults hb;
    float endPoints[18];
    float startPoints[18];
    f32 fConv;

    stateA = (ObjHitsPriorityState*)objA->anim.hitReactState;
    mask2 = objB == objA ? stateA->objectHitMask >> 4 : stateA->objectHitMask & 0xf;
    if ((mask2 != 0) && (stateA->suppressOutgoingHits == 0)) {
        stateB = (ObjHitsPriorityState*)objB->anim.hitReactState;
        if ((stateB->secondaryShapeFlags & OBJHITS_SHAPE_MODEL_HIT_VOLUMES) != 0) {
            modelBank = ObjHits_GetActiveModel(objB);
            modelFile = modelBank->file;
            hitVolumes = (ModelHitSphereDef*)modelFile->hitVolumes;
            bits = modelBank->bufferFlags >> 2 & 1;
            curSpheres = (f32*)modelBank->hitVolumeSphereBuffers[bits];
            prevSpheres = (int)modelBank->hitVolumeSphereBuffers[bits ^ 1];
            pointCount = 0;
            for (i = 0; i < (int)(u32)modelFile->hitVolumeCount; i = i + 1) {
                if ((i == hitVolumes[i].sphereIndex) && ((mask2 & 1 << hitVolumes[i].maskBit) != 0)) {
                    bits = hitVolumes[i].linkedSpheres;
                    if (bits != 0) {
                        for (; (u16)bits != 0; bits = (u16)((bits & 0xffff) << 4)) {
                            sphereIdx = (((u16)bits & 0xf000) >> 0xc) + i & 0xffff;
                            if (pointCount < 4) {
                                float* curEntry;
                                float* prevEntry;
                                int sphereOff = sphereIdx * 0x10;
                                curEntry = (float*)((u8*)curSpheres + sphereOff);
                                endPoints[pointCount * 3] = playerMapOffsetX + curEntry[1];
                                endPoints[pointCount * 3 + 1] = curEntry[2];
                                endPoints[pointCount * 3 + 2] = playerMapOffsetZ + curEntry[3];
                                prevEntry = (float*)((u8*)prevSpheres + sphereOff);
                                startPoints[pointCount * 3] = playerMapOffsetX + prevEntry[1];
                                startPoints[pointCount * 3 + 1] = prevEntry[2];
                                startPoints[pointCount * 3 + 2] = playerMapOffsetZ + prevEntry[3];
                                hb.radii[pointCount] = *curEntry;
                                hb.surfaceTypes[pointCount] = -1;
                                hb.queryTypes[pointCount] = 7;
                                pointCount = pointCount + 1;
                            }
                        }
                    } else {
                        if (pointCount < 4) {
                            endPoints[pointCount * 3] = playerMapOffsetX + curSpheres[i * 4 + 1];
                            endPoints[pointCount * 3 + 1] = curSpheres[i * 4 + 2];
                            endPoints[pointCount * 3 + 2] = playerMapOffsetZ + curSpheres[i * 4 + 3];
                            startPoints[pointCount * 3] = playerMapOffsetX + ((float*)prevSpheres)[i * 4 + 1];
                            startPoints[pointCount * 3 + 1] = ((float*)prevSpheres)[i * 4 + 2];
                            startPoints[pointCount * 3 + 2] =
                                playerMapOffsetZ + ((float*)prevSpheres)[i * 4 + 3];
                            hb.radii[pointCount] = curSpheres[i * 4];
                            hb.surfaceTypes[pointCount] = -1;
                            hb.queryTypes[pointCount] = 7;
                            pointCount = pointCount + 1;
                        }
                    }
                }
            }
        } else {
            endPoints[0] = objA->anim.worldPosX;
            endPoints[1] = objA->anim.worldPosY;
            endPoints[2] = objA->anim.worldPosZ;
            startPoints[0] = objA->anim.previousWorldPosX;
            startPoints[1] = objA->anim.previousWorldPosY;
            startPoints[2] = objA->anim.previousWorldPosZ;
            fConv = (f32)(u32)(objA)->anim.modelInstance->fallbackHitSphereRadius;
            if (fConv < gObjHitsScalarTenth[0]) {
                fConv = gObjHitsScalarTenth[0];
            }
            hb.radii[0] = fConv;
            hb.surfaceTypes[0] = -1;
            hb.queryTypes[0] = 7;
            pointCount = 1;
        }
        if (pointCount != 0) {
            hitDetect_calcSweptSphereBounds(&bounds, startPoints, endPoints, hb.radii, pointCount);
            trackIntersectBroadphase(objB, &bounds, stateB->trackContactMask, 1);
            contact = trackGetIntersect(objB, startPoints, endPoints, pointCount, &hb, 0);
            if (contact != 0) {
                if ((contact & 1) != 0) {
                    pointCount = 0;
                } else if ((contact & 2) != 0) {
                    pointCount = 1;
                } else if ((contact & 4) != 0) {
                    pointCount = 2;
                } else {
                    pointCount = 3;
                }
                stateB->contactHitVolume = hb.surfaceTypes[pointCount];
                stateB->contactPosX = endPoints[pointCount * 3];
                stateB->contactPosY = endPoints[pointCount * 3 + 1];
                stateB->contactPosZ = endPoints[pointCount * 3 + 2];
                if (hb.objects[pointCount] != NULL) {
                    stateB->contactFlags = stateB->contactFlags | OBJHITS_CONTACT_FLAG_KIND_NONZERO;
                } else {
                    stateB->contactFlags = stateB->contactFlags | OBJHITS_CONTACT_FLAG_KIND0;
                }
            }
        }
    }
}

void ObjHits_Update(int objectCount) {
    u8 skeletonScratchB[1036];
    u8 skeletonScratchC[1040];
    ObjHitsSkeletonHit skeletonHits[OBJHITS_SKELETON_HIT_CAPACITY + 2];
    u8 skeletonScratchD[100];
    u8 skeletonScratchE[100];
    GameObject* listObj;
    ObjHitsSweepEntry** entrySlot;
    ObjHitsSweepEntry* nextEntry;
    int slotIndex;
    GameObject* obj;
    ObjHitsPriorityState* objState;
    int candidateIndex;
    int slotCount;
    GameObject* candObj;
    ObjHitsSweepEntry** entrySlotBase;
    ObjHitsPriorityState* candState;
    int currentIndex;
    GameObject* attachedObj;
    ObjHitsSweepEntry* sweepEntries;
    int listCount;
    int startIndex;
    ObjHitsSweepEntry* entry;
    ObjHitsSweepEntry* candidateEntry;
    GameObject** objectList;
    GameObject* candAttachedObj;
    f32 axisDiff;
    f32 diff;
    int hitVolumeIndex;

    objectList = ObjList_GetObjects(&startIndex, &listCount);
    sweepEntries = gObjHitsSweepEntries;
    sweepEntries->minX = -36288576.0f;
    sweepEntries->maxX = -36288576.0f;
    gObjHitsSweepEntryPtrs[0] = sweepEntries;
    slotCount = 1;
    entrySlotBase = &gObjHitsSweepEntryPtrs[1];
    nextEntry = &sweepEntries[1];
    entrySlot = entrySlotBase;
    for (; objectCount > 0; objectCount--) {
        {
            ObjHitsPriorityState* listState;

            listObj = *objectList;
            listState = (ObjHitsPriorityState*)listObj->anim.hitReactState;
            if (listState != NULL) {
                if (((listState->flags &
                      (OBJHITS_PRIORITY_STATE_ENABLED | OBJHITS_PRIORITY_STATE_NO_SEPARATION_RESPONSE)) != 0) &&
                    (listState->shapeFlags != 8) && (slotCount < OBJHITS_SWEEP_ENTRY_CAPACITY)) {
                    *entrySlot = nextEntry;
                    (*entrySlot)->obj = listObj;
                    (*entrySlot)->minX = listObj->anim.worldPosX - listState->sweepRadiusX;
                    nextEntry++;
                    entrySlot++;
                    gObjHitsSweepEntryPtrs[slotCount++]->maxX =
                        listObj->anim.worldPosX + listState->sweepRadiusX;
                }
                listState->flags = listState->flags & ~OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED;
                listState->contactFlags = 0;
                listState->contactHitVolume = -1;
                *(int*)listState = 0;
                attachedObj = listObj->childObjs[0];
                if ((attachedObj != 0) && (attachedObj->anim.classId == 0x2d)) {
                    listState = ObjAnim_GetPriorityHitState(&attachedObj->anim);
                    listState->flags = listState->flags & ~OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED;
                    listState->contactFlags = 0;
                    listState->contactHitVolume = -1;
                    *(int*)listState = 0;
                }
            }
            objectList++;
        }
    }
    ObjHits_SortSweepEntries(gObjHitsSweepEntryPtrs, slotCount);
    currentIndex = 1;
    slotIndex = 1;
    entrySlot = entrySlotBase;
    for (; slotIndex < slotCount; entrySlot++, slotIndex++) {
        entry = *entrySlot;
        obj = entry->obj;
        objState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        attachedObj = obj->childObjs[0];
        if ((attachedObj != 0) && ((ObjAnim_GetPriorityHitState(&attachedObj->anim) == NULL) ||
                                   ((ObjAnim_GetPriorityHitState(&attachedObj->anim)->flags &
                                     OBJHITS_PRIORITY_STATE_ENABLED) == 0))) {
            attachedObj = 0;
        }
        if ((objState->flags & 4) != 0) {
            ObjHitsSweepEntry** skipSlot;
            candidateIndex = currentIndex;
            skipSlot = &gObjHitsSweepEntryPtrs[currentIndex];
            for (; (entry->minX > (*skipSlot)->maxX) && (candidateIndex < slotCount); candidateIndex++) {
                skipSlot++;
            }
            currentIndex = candidateIndex;
            while ((candidateIndex < slotCount) &&
                   ((*entrySlot)->maxX > gObjHitsSweepEntryPtrs[candidateIndex]->minX)) {
                candidateEntry = gObjHitsSweepEntryPtrs[candidateIndex];
                if ((*entrySlot)->minX > candidateEntry->maxX) {
                    candidateIndex++;
                    continue;
                }
                {
                    candObj = candidateEntry->obj;
                    candState = (ObjHitsPriorityState*)candObj->anim.hitReactState;
                    if ((slotIndex != candidateIndex) && (obj->anim.parent != candObj)) {
                        diff = obj->anim.worldPosZ - candObj->anim.worldPosZ;
                        diff = (diff > gObjHitsScalarZero[0]) ? diff : -diff;
                        if (diff < objState->primaryRadiusXZ + candState->primaryRadiusXZ) {
                            diff = obj->anim.worldPosY - candObj->anim.worldPosY;
                            diff = (diff > *(const f32*)&gObjHitsScalarZero[0]) ? diff : -diff;
                            if ((diff < objState->primaryRadiusY + candState->primaryRadiusY) &&
                                ((objState->flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0) &&
                                ((candState->flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0) &&
                                (((candState->flags & 4) == 0) || (slotIndex >= candidateIndex)) &&
                                ((obj->anim.modelInstance->runtimeSourceHitMask &
                                  candState->targetMask) != 0) &&
                                ((candObj->anim.modelInstance->runtimeSourceHitMask &
                                  objState->targetMask) != 0)) {
                                if ((candState->shapeFlags & OBJHITS_SHAPE_SKELETON) != 0) {
                                    ObjHits_CheckSkeletonPair(candObj, obj, skeletonHits, skeletonScratchB,
                                                              skeletonScratchC, skeletonScratchD, skeletonScratchE, 0);
                                } else if ((objState->shapeFlags & OBJHITS_SHAPE_SKELETON) != 0) {
                                    ObjHits_CheckSkeletonPair(obj, candObj, skeletonHits, skeletonScratchB,
                                                              skeletonScratchC, skeletonScratchD, skeletonScratchE, 0);
                                } else if ((objState->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES) ||
                                           (candState->shapeFlags == OBJHITS_SHAPE_MODEL_HIT_VOLUMES)) {
                                    if ((objState->lateralResponseWeight != 0) ||
                                        (candState->lateralResponseWeight != 0)) {
                                        ObjHits_CheckHitVolumes(obj, candObj, obj, 0, 1, 0xffffffff, 0);
                                    }
                                } else if ((objState->lateralResponseWeight != 0) ||
                                           (candState->lateralResponseWeight != 0)) {
                                    ObjHits_DetectObjectPair(obj, candObj);
                                }
                            }
                        }
                        if (diff < objState->secondaryRadiusXZ + candState->secondaryRadiusXZ) {
                            axisDiff =
                                (obj->anim.worldPosY - candObj->anim.worldPosY >
                                 gObjHitsScalarZero[0])
                                    ? obj->anim.worldPosY - candObj->anim.worldPosY
                                    : -(obj->anim.worldPosY - candObj->anim.worldPosY);
                            if ((axisDiff < objState->secondaryRadiusY + candState->secondaryRadiusY) &&
                                ((objState->flags & OBJHITS_PRIORITY_STATE_HIT_EXCLUDED) == 0) &&
                                ((candState->flags & OBJHITS_PRIORITY_STATE_HIT_EXCLUDED) == 0) &&
                                ((objState->sourceMask & candState->targetMask) != 0) &&
                                (((candState->sourceMask & 0x80) != 0) ||
                                 ((candState->sourceMask & objState->targetMask) != 0))) {
                                candAttachedObj = candObj->childObjs[0];
                                if ((candAttachedObj != 0) &&
                                    ((ObjAnim_GetPriorityHitState(&candAttachedObj->anim) == NULL) ||
                                     ((ObjAnim_GetPriorityHitState(&candAttachedObj->anim)->flags &
                                       OBJHITS_PRIORITY_STATE_ENABLED) == 0))) {
                                    candAttachedObj = 0;
                                }
                                ObjHits_CheckObjectHitVolumes(obj, candObj, attachedObj, candAttachedObj, timeDelta);
                            }
                        }
                    }
                }
                candidateIndex++;
            }
        }
    }
    for (slotIndex = 1, entrySlot = entrySlotBase; slotIndex < slotCount; entrySlot++, slotIndex++) {
        obj = (*entrySlot)->obj;
        if ((((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &
             OBJHITS_PRIORITY_STATE_TRACK_CONTACT) != 0) {
            ObjHits_CheckTrackContact(obj, obj);
            attachedObj = obj->childObjs[0];
            if (attachedObj != 0) {
                ObjHits_CheckTrackContact(obj, attachedObj);
            }
        }
    }
    for (slotIndex = 1; slotIndex < slotCount; entrySlotBase++, slotIndex++) {
        obj = (*entrySlotBase)->obj;
        objState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        objState->localPosX = obj->anim.localPosX;
        objState->localPosY = obj->anim.localPosY;
        objState->localPosZ = obj->anim.localPosZ;
        if (obj->anim.parent != NULL) {
            Obj_TransformLocalPointToWorld(objState->localPosX, objState->localPosY, objState->localPosZ,
                                           &objState->worldPosX, &objState->worldPosY, &objState->worldPosZ,
                                           obj->anim.parent);
        } else {
            objState->worldPosX = obj->anim.localPosX;
            objState->worldPosY = obj->anim.localPosY;
            objState->worldPosZ = obj->anim.localPosZ;
        }
        objState->activeHitboxMode = 0;
        objState->flags = objState->flags & ~OBJHITS_PRIORITY_STATE_HITBOX_BUFFER_CACHED;
        if (((objState->priorityHitCount != 0) ||
             ((objState->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED) != 0)) &&
            ((objState->flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0) && ((objState->flags & 0x4000) == 0)) {
            obj->anim.velocityX =
                oneOverTimeDelta * (obj->anim.localPosX - obj->anim.previousLocalPosX);
            obj->anim.velocityZ =
                oneOverTimeDelta * (obj->anim.localPosZ - obj->anim.previousLocalPosZ);
        }
    }
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex = 0] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
}

char sObjHitsTooManyHitSpheresWarning[] = "HIT VOLUMES: an object has too many hit spheres\n";

f32 gObjHitsResponseDominanceRatio = 0.4f;
char sObjHitReactResetString[7] = "reset\n";

const StaffCollisionColorArgs gObjHitReactEffectColorArgs = {8, 0xB4, 0xF0, 0xFF};

u32 ObjHitReact_Update(GameObject* obj, ObjHitReactEntry* reactionEntryTable, u32 reactionEntryCount, u32 reactionState,
                       float* reactionStepScale) {
    ObjAnimDef* animDef;
    ObjAnimComponent* objAnim;
    int moveEnded;
    int hitType;
    ObjHitReactEntry* reactionEntry;
    StaffCollisionInterface** effectResource;
    bool sfxActive;
    PartFxSpawnParams effectParams;
    StaffCollisionColorArgs effectColorArgs;
    int hitSphereIndex;

    objAnim = &obj->anim;
    effectColorArgs = gObjHitReactEffectColorArgs;
    if ((reactionState & OBJHITREACT_REACTION_STATE_MASK) != OBJHITREACT_REACTION_STATE_INACTIVE) {
        OSReport(sObjHitReactHitstateFrameString, objAnim->currentMoveProgress);
        moveEnded = ObjAnim_AdvanceCurrentMove(obj, (double)*reactionStepScale, (double)timeDelta, NULL);
        if (moveEnded != 0) {
            OSReport(sObjHitReactResetString);
            reactionState = OBJHITREACT_REACTION_STATE_INACTIVE;
        }
    }
    hitType = ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), 0, &hitSphereIndex, 0, &effectParams.posX,
                                                 &effectParams.posY, &effectParams.posZ);
    if (hitType != 0) {
        ObjAnimBank* bank = ObjAnim_GetActiveBank(objAnim);
        effectParams.posX = effectParams.posX + playerMapOffsetX;
        effectParams.posZ = effectParams.posZ + playerMapOffsetZ;
        effectParams.scale = gObjHitsScalarOne[0];
        effectParams.rotZ = 0;
        effectParams.rotY = 0;
        effectParams.rotX = 0;
        animDef = bank->animDef;
        hitSphereIndex = ObjAnim_GetHitReactEntryIndex(animDef, hitSphereIndex);
        if (hitSphereIndex >= (int)(reactionEntryCount & OBJHITREACT_ENTRY_COUNT_MASK)) {
            OSReport(sObjHitReactSphereOverflowString, hitSphereIndex);
            hitSphereIndex = 0;
        }
        reactionEntry = &reactionEntryTable[hitSphereIndex];
        if (hitType != OBJHITREACT_COLLISION_SKIP_REACTION) {
            if ((reactionEntry->primaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
                (sfxActive = Sfx_IsPlayingFromObject(obj, (u16)reactionEntry->primaryHitSfxId),
                 !sfxActive)) {
                Sfx_PlayFromObject(obj, reactionEntry->primaryHitSfxId);
            }
            if ((reactionEntry->secondaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
                (sfxActive = Sfx_IsPlayingFromObject(obj, (u16)reactionEntry->secondaryHitSfxId),
                 !sfxActive)) {
                Sfx_PlayFromObject(obj, reactionEntry->secondaryHitSfxId);
            }
            if (reactionEntry->hitEffectMode == OBJHITREACT_HIT_FX_MODE_EFFECT) {
                effectResource = Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID, OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
                (*effectResource)
                    ->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE, OBJHITREACT_HIT_EFFECT_MODE, &effectParams,
                            OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS, OBJHITREACT_HIT_EFFECT_NO_SOURCE, &effectColorArgs);
                if (effectResource != NULL) {
                    Resource_Release(effectResource);
                }
            } else {
                objDoHitParticleFx((void*)obj, 0.014f, &effectParams, OBJHITREACT_ALT_EFFECT_COUNT, NULL);
            }
        }
        if (((reactionState & OBJHITREACT_REACTION_STATE_MASK) == OBJHITREACT_REACTION_STATE_INACTIVE) &&
            (reactionEntry->reactionMoveId > OBJHITREACT_NO_REACTION_ANIM)) {
            ObjAnim_SetCurrentMove(obj, reactionEntry->reactionMoveId, gObjHitsScalarZero[0], 0);
            *reactionStepScale = reactionEntry->reactionStepScale;
            reactionState = OBJHITREACT_REACTION_STATE_ACTIVE;
        }
    }
    return reactionState;
}

void ObjHitReact_ResetActiveObjects(int objectCount) {
    ObjHitReactState* hitState;
    ObjAnimComponent* objAnim;
    ObjAnimComponent** objectListCursor;
    int stateActive;
    int resetPending;
    int objectListCount;
    int startIndex;

    objectListCursor = (ObjAnimComponent**)ObjList_GetObjects(&startIndex, &objectListCount);
    gObjHitReactResetObjectCount = 0;
    while (objectCount > 0) {
        objAnim = *objectListCursor;
        hitState = objAnim->hitReactState;
        if (hitState != NULL) {
            stateActive = hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED;
            if (stateActive != 0) {
                resetPending = hitState->shapeFlags & OBJHITREACT_SHAPE_RESET_UPDATE;
                if (resetPending != 0) {
                    if (gObjHitReactResetObjectCount < OBJHITREACT_MAX_RESET_OBJECTS) {
                        gObjHitReactResetObjects[gObjHitReactResetObjectCount++] = objAnim;
                    }
                    hitState->activeHit = 0;
                    hitState->flags = (s16)(hitState->flags & ~OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED);
                    hitState->resetFrameCount = OBJHITREACT_RESET_FRAME_COUNT;
                }
            }
        }
        objectListCursor = objectListCursor + 1;
        objectCount = objectCount + -1;
    }
}

int ObjHitbox_AllocRotatedBounds(ObjHitbox* hitbox, u32 arena) {
    ObjHitboxTransformState* transformState;

    transformState = (ObjHitboxTransformState*)roundUpTo4(arena);
    hitbox->transformState = transformState;
    if (hitbox->transformState != NULL) {
        hitbox->transformState->activeMatrixIndex = 0;
        hitbox->transformState->resetFrames = OBJHITBOX_ROTATED_BOUNDS_RESET_FRAMES;
        hitbox->transformState->contactObjectCount = 0;
        ObjHitbox_UpdateRotatedBounds(hitbox, 1);
        ObjHitbox_UpdateRotatedBounds(hitbox, 1);
    }
    return (u32)transformState + sizeof(ObjHitboxTransformState);
}

void ObjHitReact_LoadMoveEntries(ObjAnimComponent* objAnim, ObjAnimBank* bank, int objType, ObjHitReactState* hitState,
                                 int moveId, int async) {
    int moveEntryWordIndex;
    s16* moveEntryTable;
    s16* moveEntry;
    s16 entryByteOffset;

    moveEntryTable = (s16*)objAnim->modelInstance->hitReactMoveTable;
    hitState->activeEntryByteCount = 0;
    if (moveEntryTable != NULL) {
        for (moveEntryWordIndex = 0, moveEntry = moveEntryTable;
             ((ObjHitReactMoveEntry*)moveEntry)->moveId != OBJHITREACT_MOVE_ID_END;
             moveEntry += OBJHITREACT_MOVE_ENTRY_SHORT_COUNT,
            moveEntryWordIndex += OBJHITREACT_MOVE_ENTRY_SHORT_COUNT) {
            if (moveId == ((ObjHitReactMoveEntry*)moveEntry)->moveId) {
                moveEntry = &moveEntryTable[moveEntryWordIndex];
                entryByteOffset = ((ObjHitReactMoveEntry*)moveEntry)->firstEntryByteOffset;
                hitState->activeEntryByteCount = ((ObjHitReactMoveEntry*)moveEntry)->entryByteCount;
                if (hitState->activeEntryByteCount > hitState->entryBufferByteCapacity) {
                    hitState->activeEntryByteCount = hitState->entryBufferByteCapacity;
                }
                if (async == 0) {
                    getTabEntry(hitState->entries, OBJHITREACT_ENTRY_TAB_FILE_ID, entryByteOffset,
                                hitState->activeEntryByteCount);
                    return;
                }
                fileLoadToBufferOffset(OBJHITREACT_ENTRY_TAB_FILE_ID, hitState->entries, entryByteOffset,
                                       hitState->activeEntryByteCount);
                return;
            }
        }
    }
    return;
}

u32 ObjHitReact_InitState(int objType, ObjAnimBank* bank, ObjHitReactState* hitState, u32 entryArena,
                          ObjAnimComponent* objAnim) {
    ObjHitReactEntry* entries;

    if (bank == NULL) {
        return entryArena;
    }
    hitState->entryBufferByteCapacity = OBJHITREACT_ENTRY_ARENA_BYTES;
    entries = (ObjHitReactEntry*)roundUpTo8(entryArena);
    hitState->entries = entries;
    entryArena = (u32)entries + hitState->entryBufferByteCapacity;
    hitState->activeHitboxMode = OBJHITREACT_ACTIVE_HITBOX_MODE;
    if ((hitState->shapeFlags & OBJHITS_SHAPE_RESET_MODE_MASK) != 0) {
        hitState->resetHitboxMode = OBJHITREACT_RESET_HITBOX_MODE;
    }
    ObjHitReact_LoadMoveEntries(objAnim, bank, objType, hitState, 0, 1);
    return entryArena;
}

char sObjHitReactHitstateFrameString[] = "hitstate frame=%f\n";
char sObjHitReactSphereOverflowString[] = "objHitReact.c: sphere overflow! %d\n";

void ObjHitbox_SetStateIndex(GameObject* object, ObjHitReactState* hitStatePtr, int stateIndex) {
    ObjHitsPriorityState* priorityState;
    int modelOrSlotIndex;
    ObjHitsPriorityWorkSlot* workSlot;

    modelOrSlotIndex = object->anim.modelInstance->modelCount;
    if (stateIndex >= modelOrSlotIndex) {
        stateIndex = modelOrSlotIndex - 1;
    } else if (stateIndex < 0) {
        stateIndex = 0;
    }
    priorityState = (ObjHitsPriorityState*)hitStatePtr;
    if (priorityState->stateIndex == stateIndex) {
        return;
    }
    for (modelOrSlotIndex = 0; (s16)modelOrSlotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT;
         modelOrSlotIndex++) {
        workSlot = &gObjHitsPriorityHitStates[modelOrSlotIndex];
        if ((workSlot->active != 0) && (workSlot->object == object)) {
            workSlot->active = 0;
        }
    }
    priorityState->stateIndex = stateIndex;
    return;
}

void ObjHits_SetTargetMask(GameObject* obj, u8 targetMask) {
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState == 0) {
        return;
    }
    hitState->targetMask = targetMask;
    return;
}

void ObjHitbox_SetSphereRadius(ObjAnimComponent* obj, s16 radius) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;

    if (hitState != 0) {
        if ((hitState->shapeFlags & OBJHITS_SHAPE_SPHERE) != 0) {
            hitState->primaryRadius = radius;
            hitState->primaryRadiusSquared = (float)(s32)hitState->primaryRadius * (float)(s32)hitState->primaryRadius;
            hitState->primaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusY) {
                hitState->primaryRadiusY = (float)(s32)hitState->primaryRadius;
            }
            hitState->primaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusXZ) {
                hitState->primaryRadiusXZ = (float)(s32)hitState->primaryRadius;
            }
        }

        if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_SPHERE) != 0) {
            hitState->secondaryRadius = radius;
            hitState->secondaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->secondaryRadiusY) {
                hitState->secondaryRadiusY = (float)(s32)hitState->secondaryRadius;
            }
            hitState->secondaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->secondaryRadiusXZ) {
                hitState->secondaryRadiusXZ = (float)(s32)hitState->secondaryRadius;
            }
        }

        hitState->sweepRadiusX = hitState->primaryRadiusXZ;
        if (hitState->secondaryRadiusXZ > hitState->sweepRadiusX) {
            hitState->sweepRadiusX = hitState->secondaryRadiusXZ;
        }
    }
    return;
}

void ObjHitbox_SetCapsuleBounds(ObjAnimComponent* obj, s16 radius, s16 verticalMin, s16 verticalMax) {
    ObjHitsPriorityState* hitState;
    float absMin;
    float absMax;
    s32 absVal;
    s16 r16 = radius;
    s16 vmin = verticalMin;
    s16 vmax = verticalMax;

    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState != 0) {
        if ((hitState->shapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) {
            hitState->primaryCapsuleOffsetA = vmin;
            hitState->primaryCapsuleOffsetB = vmax;
            hitState->primaryRadius = r16;
            hitState->primaryRadiusSquared = (float)(s32)hitState->primaryRadius * (float)(s32)hitState->primaryRadius;
            hitState->capsuleScale = OBJHITBOX_DEFAULT_CAPSULE_SCALE;
            hitState->primaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            absVal = vmin;
            if (absVal < 0) {
                absVal = -absVal;
            }
            absMin = (float)absVal;
            absVal = vmax;
            if (absVal < 0) {
                absVal = -absVal;
            }
            absMax = (float)absVal;
            if (absMin > absMax) {
                absMax = absMin;
            }
            if (absMax > hitState->primaryRadiusY) {
                hitState->primaryRadiusY = absMax;
            }
            hitState->primaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusXZ) {
                hitState->primaryRadiusXZ = (float)(s32)hitState->primaryRadius;
            }
        }
        if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) {
            hitState->secondaryCapsuleOffsetA = vmin;
            hitState->secondaryCapsuleOffsetB = vmax;
            hitState->secondaryRadius = r16;
            hitState->secondaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
            absVal = vmin;
            if (absVal < 0) {
                absVal = -absVal;
            }
            absMin = (float)absVal;
            absVal = vmax;
            if (absVal < 0) {
                absVal = -absVal;
            }
            absMax = (float)absVal;
            if (absMin > absMax) {
                absMax = absMin;
            }
            if (absMax > hitState->secondaryRadiusY) {
                hitState->secondaryRadiusY = absMax;
            }
            hitState->secondaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
            if ((float)(s32)hitState->primaryRadius > hitState->secondaryRadiusXZ) {
                hitState->secondaryRadiusXZ = (float)(s32)hitState->secondaryRadius;
            }
        }
        hitState->sweepRadiusX = hitState->primaryRadiusXZ;
        if (hitState->secondaryRadiusXZ > hitState->sweepRadiusX) {
            hitState->sweepRadiusX = hitState->secondaryRadiusXZ;
        }
    }
    return;
}

void ObjHits_ClearHitVolumes(ObjAnimComponent* obj) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;
    hitState->hitVolumePriority = 0;
    hitState->hitVolumeId = 0;
    hitState->objectHitMask = 0;
    hitState->skeletonHitMask = 0;
}

void ObjHits_SetHitVolumeMasks(ObjAnimComponent* obj, int hitVolume, int hitType, int sourceMask) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;
    hitState->hitVolumePriority = hitVolume;
    hitState->hitVolumeId = hitType;

    if (sourceMask == 0) {
        return;
    }

    hitState->objectHitMask = sourceMask << 4;
    hitState->skeletonHitMask = sourceMask << 4;
}

void ObjHits_SetHitVolumeSlot(ObjAnimComponent* obj, int hitVolume, int hitType, int sourceSlot) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;

    if (hitState == 0) {
        return;
    }

    hitState->hitVolumePriority = hitVolume;
    hitState->hitVolumeId = hitType;

    if (sourceSlot == -1) {
        return;
    }

    hitState->objectHitMask = 1 << (sourceSlot + 4);
    hitState->skeletonHitMask = 1 << (sourceSlot + 4);
}

void ObjHits_ClearSourceMask(ObjAnimComponent* obj, int sourceMask) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;
    hitState->sourceMask &= ~sourceMask;
}

void ObjHits_SetSourceMask(ObjAnimComponent* obj, u8 sourceMask) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;
    hitState->sourceMask |= sourceMask;
}

void ObjHits_ClearFlags(ObjAnimComponent* obj, int flags) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;
    hitState->flags &= ~flags;
}

void ObjHits_SetFlags(ObjAnimComponent* obj, int flags) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;
    hitState->flags |= flags;
}

void ObjHits_MarkObjectPositionDirty(ObjAnimComponent* obj) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->hitReactState;
    hitState->flags |= OBJHITS_PRIORITY_STATE_POSITION_DIRTY;
}

void ObjHits_SyncObjectPositionIfDirty(GameObject* obj) {
    ObjHitsPriorityState* hitState;
    s16 flags;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState == 0) {
        return;
    }
    flags = hitState->flags;
    if ((flags & OBJHITS_PRIORITY_STATE_POSITION_DIRTY) == 0) {
        return;
    }
    hitState->flags = (s16)(flags & ~OBJHITS_PRIORITY_STATE_POSITION_DIRTY);
    hitState->localPosX = obj->anim.localPosX;
    hitState->localPosY = obj->anim.localPosY;
    hitState->localPosZ = obj->anim.localPosZ;
    hitState->worldPosX = obj->anim.worldPosX;
    hitState->worldPosY = obj->anim.worldPosY;
    hitState->worldPosZ = obj->anim.worldPosZ;
    return;
}

void ObjHits_DisableObject(GameObject* obj) {
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState == 0) {
        return;
    }
    hitState->flags = (s16)(hitState->flags & ~OBJHITS_PRIORITY_STATE_ENABLED);
    return;
}

void ObjHits_EnableObject(GameObject* obj) {
    ObjHitsPriorityState* hitState;
    s16 flags;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState == 0) {
        return;
    }
    flags = hitState->flags;
    if ((flags & OBJHITS_PRIORITY_STATE_ENABLED) != 0) {
        return;
    }
    hitState->flags = (s16)(flags | OBJHITS_PRIORITY_STATE_ENABLED);
    hitState->localPosX = obj->anim.localPosX;
    hitState->localPosY = obj->anim.localPosY;
    hitState->localPosZ = obj->anim.localPosZ;
    hitState->worldPosX = obj->anim.worldPosX;
    hitState->worldPosY = obj->anim.worldPosY;
    hitState->worldPosZ = obj->anim.worldPosZ;
    return;
}

int ObjHits_IsObjectEnabled(ObjAnimComponent* obj) {
    return ((ObjHitsPriorityState*)obj->hitReactState)->flags & OBJHITS_PRIORITY_STATE_ENABLED;
}

void ObjHits_SyncObjectPosition(GameObject* obj) {
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState == 0) {
        return;
    }
    hitState->localPosX = obj->anim.localPosX;
    hitState->localPosY = obj->anim.localPosY;
    hitState->localPosZ = obj->anim.localPosZ;
    hitState->worldPosX = obj->anim.worldPosX;
    hitState->worldPosY = obj->anim.worldPosY;
    hitState->worldPosZ = obj->anim.worldPosZ;
    return;
}

int ObjHits_AllocObjectState(GameObject* obj, u32 arena) {
    u32 stateArena;
    ObjHitsPriorityState* hitState;

    stateArena = roundUpTo4(arena);
    obj->anim.hitReactState = (ObjHitReactState*)stateArena;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    ObjHits_RefreshObjectState(obj);
    hitState->activeHitboxMode = OBJHITS_ACTIVE_HITBOX_MODE;
    if ((hitState->shapeFlags & OBJHITS_SHAPE_RESET_MODE_MASK) != 0) {
        hitState->resetHitboxMode = OBJHITS_RESET_HITBOX_MODE;
    }
    return stateArena + sizeof(ObjHitsPriorityState);
}

void ObjHits_RefreshObjectState(GameObject* object) {
    ObjAnimComponent* obj;
    ObjHitsPriorityState* hitState;
    ObjAnimBank* activeBank;
    short capsuleOffsetA;
    short capsuleOffsetB;

    obj = &object->anim;
    hitState = (ObjHitsPriorityState*)obj->hitReactState;
    if (hitState != 0) {
        hitState->flags = obj->modelInstance->hitboxFlags;
        hitState->shapeFlags = obj->modelInstance->primaryHitboxShapeFlags;
        if ((hitState->shapeFlags & OBJHITS_SHAPE_SKELETON) != 0) {
            activeBank = ObjAnim_GetActiveBank(obj);
            if (((activeBank->animDef->flags & OBJANIM_DEF_FLAG_SKELETON_HITBOXES) == 0) ||
                (*(void**)(((int*)activeBank) + 5) == 0)) {
                hitState->shapeFlags &= ~OBJHITS_SHAPE_SKELETON;
            }
        }
        hitState->lateralResponseWeight = obj->modelInstance->lateralResponseWeight;
        hitState->axialResponseWeight = obj->modelInstance->axialResponseWeight;
        hitState->primaryRadius = obj->modelInstance->primaryHitboxRadius;
        hitState->primaryCapsuleOffsetA = obj->modelInstance->primaryCapsuleOffsetA;
        hitState->primaryCapsuleOffsetB = obj->modelInstance->primaryCapsuleOffsetB;
        hitState->stateIndex = (s8)(int)obj->modelInstance->hitboxStateIndex;
        hitState->capsuleScale = OBJHITBOX_DEFAULT_CAPSULE_SCALE;
        hitState->primaryRadiusSquared = (float)(s32)hitState->primaryRadius * (float)(s32)hitState->primaryRadius;
        hitState->secondaryShapeFlags = obj->modelInstance->secondaryHitboxShapeFlags;
        hitState->secondaryRadius = obj->modelInstance->secondaryHitboxRadius;
        hitState->secondaryCapsuleOffsetA = obj->modelInstance->secondaryCapsuleOffsetA;
        hitState->secondaryCapsuleOffsetB = obj->modelInstance->secondaryCapsuleOffsetB;
        hitState->primaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
        if ((hitState->shapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) {
            capsuleOffsetA = (hitState->primaryCapsuleOffsetA < 0) ? -hitState->primaryCapsuleOffsetA
                                                                   : hitState->primaryCapsuleOffsetA;
            capsuleOffsetB = (hitState->primaryCapsuleOffsetB < 0) ? -hitState->primaryCapsuleOffsetB
                                                                   : hitState->primaryCapsuleOffsetB;
            if (capsuleOffsetA > capsuleOffsetB) {
                capsuleOffsetB = capsuleOffsetA;
            }
            if ((float)(s32)capsuleOffsetB > hitState->primaryRadiusY) {
                hitState->primaryRadiusY = (float)(s32)capsuleOffsetB;
            }
        } else if ((hitState->shapeFlags & OBJHITS_SHAPE_SPHERE) != 0) {
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusY) {
                hitState->primaryRadiusY = (float)(s32)hitState->primaryRadius;
            }
        }
        hitState->primaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
        if (((hitState->shapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) ||
            ((hitState->shapeFlags & OBJHITS_SHAPE_SPHERE) != 0)) {
            if ((float)(s32)hitState->primaryRadius > hitState->primaryRadiusXZ) {
                hitState->primaryRadiusXZ = (float)(s32)hitState->primaryRadius;
            }
        }
        hitState->secondaryRadiusY = obj->hitboxScale * obj->rootMotionScale;
        if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) {
            capsuleOffsetA = (hitState->secondaryCapsuleOffsetA < 0) ? -hitState->secondaryCapsuleOffsetA
                                                                     : hitState->secondaryCapsuleOffsetA;
            capsuleOffsetB = (hitState->secondaryCapsuleOffsetB < 0) ? -hitState->secondaryCapsuleOffsetB
                                                                     : hitState->secondaryCapsuleOffsetB;
            if (capsuleOffsetA > capsuleOffsetB) {
                capsuleOffsetB = capsuleOffsetA;
            }
            if ((float)(s32)capsuleOffsetB > hitState->secondaryRadiusY) {
                hitState->secondaryRadiusY = (float)(s32)capsuleOffsetB;
            }
        } else if ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_SPHERE) != 0) {
            if ((float)(s32)hitState->secondaryRadius > hitState->secondaryRadiusY) {
                hitState->secondaryRadiusY = (float)(s32)hitState->secondaryRadius;
            }
        }
        hitState->secondaryRadiusXZ = obj->hitboxScale * obj->rootMotionScale;
        if (((hitState->secondaryShapeFlags & OBJHITS_SHAPE_CAPSULE) != 0) ||
            ((hitState->secondaryShapeFlags & OBJHITS_SHAPE_SPHERE) != 0)) {
            if ((float)(s32)hitState->secondaryRadius > hitState->secondaryRadiusXZ) {
                hitState->secondaryRadiusXZ = (float)(s32)hitState->secondaryRadius;
            }
        }
        hitState->sweepRadiusX = hitState->primaryRadiusXZ;
        if (hitState->secondaryRadiusXZ > hitState->sweepRadiusX) {
            hitState->sweepRadiusX = hitState->secondaryRadiusXZ;
        }
        hitState->sourceMask = obj->modelInstance->sourceHitMask;
        hitState->targetMask = obj->modelInstance->targetHitMask;
    }
    return;
}

int ObjHits_RecordObjectHit(GameObject* obj, GameObject* hitObj, s8 priority, int hitVolume, s8 sphereIndex) {
    ObjAnimComponent* sourceObj;
    ObjAnimComponent* targetObj;
    ObjHitsPriorityState* hitState;
    int hitSlot;
    u8 hitVolumeId;

    if (priority == '\0') {
        return 0;
    }
    sourceObj = (ObjAnimComponent*)obj;
    targetObj = (ObjAnimComponent*)hitObj;
    hitState = (ObjHitsPriorityState*)sourceObj->hitReactState;
    if ((hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED) == 0) {
        return 0;
    }
    if ((targetObj != NULL) && (targetObj->hitReactState != NULL)) {
        ((ObjHitsPriorityState*)targetObj->hitReactState)->lastHitObject = (u32)obj;
    }
    hitSlot = 0;
    hitVolumeId = hitVolume;
    while (hitSlot < hitState->priorityHitCount) {
        if ((void*)hitState->hitObjects[hitSlot] == (void*)hitObj) {
            if (hitState->priorities[hitSlot] > priority) {
                hitState->sphereIndices[hitSlot] = sphereIndex;
                hitState->priorities[hitSlot] = priority;
                hitState->hitVolumes[hitSlot] = hitVolumeId;
                hitState->hitPosX[hitSlot] = sourceObj->localPosX;
                hitState->hitPosY[hitSlot] = sourceObj->localPosY;
                hitState->hitPosZ[hitSlot] = sourceObj->localPosZ;
            }
            hitSlot = hitState->priorityHitCount + 1;
        }
        hitSlot = hitSlot + 1;
    }
    if ((hitSlot == hitState->priorityHitCount) && (hitState->priorityHitCount < OBJHITS_PRIORITY_HIT_COUNT)) {
        hitState->sphereIndices[hitState->priorityHitCount] = sphereIndex;
        hitState->priorities[hitState->priorityHitCount] = priority;
        hitState->hitVolumes[hitState->priorityHitCount] = hitVolumeId;
        hitState->hitObjects[hitState->priorityHitCount] = (int)hitObj;
        hitState->hitPosX[hitState->priorityHitCount] = sourceObj->localPosX;
        hitState->hitPosY[hitState->priorityHitCount] = sourceObj->localPosY;
        hitState->hitPosZ[hitState->priorityHitCount] = sourceObj->localPosZ;
        hitState->priorityHitCount++;
    }
    return 1;
}

int ObjHits_RecordPositionHit(GameObject* obj, GameObject* hitObj, s8 priority, int hitVolume, s8 sphereIndex,
                              f32 hitPosX, f32 hitPosY, f32 hitPosZ) {
    ObjAnimComponent* sourceObj;
    ObjAnimComponent* targetObj;
    ObjHitsPriorityState* hitState;
    int hitSlot;
    u8 hitVolumeId;

    if (priority == 0) {
        return 0;
    }
    sourceObj = (ObjAnimComponent*)obj;
    targetObj = (ObjAnimComponent*)hitObj;
    hitState = (ObjHitsPriorityState*)sourceObj->hitReactState;
    if ((hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED) == 0) {
        return 0;
    }
    if ((targetObj != NULL) && (targetObj->hitReactState != NULL)) {
        ((ObjHitsPriorityState*)targetObj->hitReactState)->lastHitObject = (u32)obj;
    }
    hitSlot = 0;
    hitVolumeId = hitVolume;
    while (hitSlot < hitState->priorityHitCount) {
        if ((void*)hitState->hitObjects[hitSlot] == (void*)hitObj) {
            if (hitState->priorities[hitSlot] > priority) {
                hitState->sphereIndices[hitSlot] = sphereIndex;
                hitState->priorities[hitSlot] = priority;
                hitState->hitVolumes[hitSlot] = hitVolumeId;
                hitState->hitPosX[hitSlot] = hitPosX;
                hitState->hitPosY[hitSlot] = hitPosY;
                hitState->hitPosZ[hitSlot] = hitPosZ;
            }
            hitSlot = hitState->priorityHitCount + 1;
        }
        hitSlot = hitSlot + 1;
    }
    if ((hitSlot == hitState->priorityHitCount) && (hitState->priorityHitCount < OBJHITS_PRIORITY_HIT_COUNT)) {
        hitState->sphereIndices[hitState->priorityHitCount] = sphereIndex;
        hitState->priorities[hitState->priorityHitCount] = priority;
        hitState->hitVolumes[hitState->priorityHitCount] = hitVolumeId;
        hitState->hitObjects[hitState->priorityHitCount] = (int)hitObj;
        hitState->hitPosX[hitState->priorityHitCount] = hitPosX;
        hitState->hitPosY[hitState->priorityHitCount] = hitPosY;
        hitState->hitPosZ[hitState->priorityHitCount] = hitPosZ;
        hitState->priorityHitCount++;
    }
    return 1;
}

void ObjHits_AddContactObject(GameObject* obj, GameObject* contactObj) {
    int contactObjectIndex;
    int contactObjectCount;
    int contactOffset;
    int i;
    int storeState;
    int transformState;

    transformState = *(int*)((int)obj + OBJHITBOX_TRANSFORM_STATE_OFFSET);
    if ((u32)transformState == 0) {
        return;
    }
    contactObjectCount = (int)*(char*)(transformState + OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET);
    if (contactObjectCount >= OBJHITBOX_CONTACT_OBJECT_COUNT) {
        return;
    }
    contactOffset = 0;
    for (i = 0; i < contactObjectCount; i++) {
        u32 entryObj = *(u32*)(transformState + contactOffset + OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET);
        if (entryObj == (u32)contactObj) {
            return;
        }
        contactOffset = contactOffset + 4;
    }
    storeState = *(int*)((u8*)obj + OBJHITBOX_TRANSFORM_STATE_OFFSET);
    contactObjectIndex = (*(char*)(transformState + OBJHITBOX_STATE_CONTACT_OBJECT_COUNT_OFFSET))++;
    *(int*)(storeState + OBJHITBOX_STATE_CONTACT_OBJECTS_OFFSET + contactObjectIndex * 4) = (int)contactObj;
}

int ObjHits_GetPriorityHitWithPosition(GameObject* obj, GameObject** outHitObject, int* outSphereIndex,
                                       u32* outHitVolume, float* outHitPosX, float* outHitPosY, float* outHitPosZ) {
    u8 hitPriority;
    int hitCount;
    ObjHitsPriorityState* hitState;
    int hitSlot;
    u8 bestPriority;
    s8 bestHitSlot;

    hitState = *(ObjHitsPriorityState**)&obj->anim.hitReactState;
    if (hitState == 0) {
        return 0;
    }
    hitCount = hitState->priorityHitCount;
    if (hitCount != 0) {
        bestPriority = OBJHITS_PRIORITY_INVALID;
        bestHitSlot = -1;
        for (hitSlot = 0; hitSlot < hitCount; hitSlot++) {
            hitPriority = hitState->priorities[hitSlot];
            if ((s8)hitPriority < (s8)bestPriority) {
                bestPriority = hitPriority;
                bestHitSlot = hitSlot;
            }
        }
        if (bestHitSlot != -1) {
            if (outHitObject != NULL) {
                *outHitObject = (GameObject*)hitState->hitObjects[bestHitSlot];
            }

            if (outSphereIndex != 0x0) {
                *outSphereIndex = hitState->sphereIndices[bestHitSlot];
            }

            if (outHitVolume != 0x0) {
                *outHitVolume = hitState->hitVolumes[bestHitSlot];
            }

            if (outHitPosX != (float*)0x0) {
                *outHitPosX = hitState->hitPosX[bestHitSlot];
                *outHitPosY = hitState->hitPosY[bestHitSlot];
                *outHitPosZ = hitState->hitPosZ[bestHitSlot];
            }

            return (s8)bestPriority;
        }
    }
    return 0;
}

int ObjHits_GetPriorityHit(GameObject* obj, GameObject** outHitObject, int* outSphereIndex, u32* outHitVolume) {
    u8 hitPriority;
    int hitCount;
    ObjHitsPriorityState* hitState;
    int hitSlot;
    u8 bestPriority;
    s8 bestHitSlot;

    hitState = *(ObjHitsPriorityState**)&obj->anim.hitReactState;
    if (hitState == 0) {
        return 0;
    }
    hitCount = hitState->priorityHitCount;
    if (hitCount != 0) {
        bestPriority = OBJHITS_PRIORITY_INVALID;
        bestHitSlot = -1;
        for (hitSlot = 0; hitSlot < hitCount; hitSlot++) {
            hitPriority = hitState->priorities[hitSlot];
            if ((s8)hitPriority < (s8)bestPriority) {
                bestPriority = hitPriority;
                bestHitSlot = hitSlot;
            }
        }
        if (bestHitSlot != -1) {
            if (outHitObject != 0x0) {
                *outHitObject = (GameObject*)hitState->hitObjects[bestHitSlot];
            }
            if (outSphereIndex != 0x0) {
                *outSphereIndex = hitState->sphereIndices[bestHitSlot];
            }
            if (outHitVolume != 0x0) {
                *outHitVolume = hitState->hitVolumes[bestHitSlot];
            }
            return (int)(s8)bestPriority;
        }
    }
    return 0;
}

void ObjHitReact_UpdateResetObjects(void) {
    ObjAnimComponent* obj;
    int objectIndex;
    int objectOffset;

    objectIndex = 0;
    objectOffset = 0;
    for (; objectIndex < gObjHitReactResetObjectCount; objectIndex = objectIndex + 1) {
        obj = gObjHitReactResetObjects[objectIndex];
        if (((obj->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) == 0) &&
            (obj->activeHitboxMode != OBJHITREACT_DISABLED_HITBOX_MODE)) {
            Obj_UpdateObject((GameObject*)obj);
        }
        objectOffset = objectOffset + 4;
    }
    objectOffset = 0;
    for (; objectOffset < gObjHitReactResetObjectCount; objectOffset = objectOffset + 1) {
        ObjHitbox_UpdateRotatedBounds((ObjHitbox*)gObjHitReactResetObjects[objectOffset], 1);
    }
    return;
}

void ObjHits_ResetWorkBuffers(void) {
    int slotIndex;

    for (slotIndex = 0; slotIndex < OBJHITS_PRIORITY_WORK_SLOT_COUNT; slotIndex++) {
        gObjHitsPriorityHitStates[slotIndex].active = 0;
    }
    gObjHitReactResetObjectCount = 0;
}

ObjAnimComponent** ObjHitReact_GetResetObjects(int* outObjectCount) {
    *outObjectCount = gObjHitReactResetObjectCount;
    return gObjHitReactResetObjects;
}

void ObjHits_InitWorkBuffers(void) {
    int hitVolumeIndex;

    gObjHitReactResetObjects =
        (ObjAnimComponent**)mmAlloc(OBJHITREACT_MAX_RESET_OBJECTS * sizeof(ObjAnimComponent*), 0xe, 0);
    gObjHitsPriorityHitStates = mmAlloc(OBJHITS_PRIORITY_WORK_SLOT_COUNT * sizeof(ObjHitsPriorityWorkSlot), 0xe, 0);
    gObjHitsWorkBuffer = mmAlloc(0x1900, 0xe, 0);
    gObjHitsPrimaryHitboxBufferScratch0 = mmAlloc(0x400, 0xe, 0);
    gObjHitsPrimaryHitboxBufferScratch1 = mmAlloc(0x400, 0xe, 0);
    gObjHitsSecondaryHitboxBufferScratch0 = mmAlloc(0x400, 0xe, 0);
    gObjHitsSecondaryHitboxBufferScratch1 = mmAlloc(0x400, 0xe, 0);
    gObjHitsPriorityHitTickDelta = gObjHitsScalarTwo[0];
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[hitVolumeIndex = 0] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    ((int*)(int)gObjHitsActiveHitVolumeObjects)[++hitVolumeIndex] = 0;
    return;
}

ObjHitsContactScratchEntry gObjHitsContactScratch[OBJHITS_CONTACT_SCRATCH_COUNT];
ObjHitsSweepEntry gObjHitsSweepEntries[OBJHITS_SWEEP_ENTRY_CAPACITY];
