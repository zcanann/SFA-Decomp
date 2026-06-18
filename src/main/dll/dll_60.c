/*
 * Drakor combat camera (DLL 0x60) - target-offset solver.
 *
 * camdrakor_computeTargetOffset produces the vector from the camera's
 * focus object to the spot the camera should aim at while tracking the
 * target's currently-active hit-volume node (target->unkE4). When the
 * active node changes between frames it kicks off a blend: the previous
 * node index is latched as the blend start and a blend weight is reset,
 * then each frame the weight is wound down (lbl_803E2548 * lbl_803DC074
 * step, floored at lbl_803E2544) and the start/target node centers are
 * lerped. Once the weight reaches the floor the offset snaps straight to
 * the target node. Shared blend state lives in the combat-camera state
 * record (DAT_803de1e0).
 */
#include "main/dll/CAM/dll_60.h"
#include "main/dll/CAM/camcombat_state.h"
#include "main/game_object.h"

extern CameraModeCombatState* DAT_803de1e0;
extern f32 lbl_803DC074;     /* per-frame blend-step scale */
extern f32 lbl_803E2540;     /* blend weight reset value */
extern f32 lbl_803E2544;     /* blend weight floor (snap-to-target) */
extern f32 lbl_803E2548;     /* blend-step base */

void camdrakor_computeTargetOffset
(CameraObject* camera, float* outX, float* outY, float* outZ, float* targetY)
{
    float weightFloor;
    float startCenterY;
    float targetCenterY;
    float startCenterZ;
    float targetCenterZ;
    float weight;
    GameObject* focus;
    GameObject* target;
    ObjHitVolumeRuntimeTransform* hitVolumes;
    ObjHitVolumeRuntimeTransform* startHitVolume;
    ObjHitVolumeRuntimeTransform* targetHitVolume;

    target = (GameObject*)camera->targetObj;
    focus = (GameObject*)camera->anim.targetObj;
    hitVolumes = target->anim.hitVolumeTransforms;
    if (target->unkE4 != DAT_803de1e0->pathBlendTargetIndex)
    {
        DAT_803de1e0->pathBlendStartIndex = DAT_803de1e0->pathBlendTargetIndex;
        DAT_803de1e0->pathBlendWeight = lbl_803E2540;
    }
    weightFloor = lbl_803E2544;
    if (DAT_803de1e0->pathBlendWeight <= weightFloor)
    {
        *outX = hitVolumes[target->unkE4].centerX - focus->anim.worldPosX;
        *outY = hitVolumes[target->unkE4].centerY - *targetY;
        *outZ = hitVolumes[target->unkE4].centerZ - focus->anim.worldPosZ;
    }
    else
    {
        DAT_803de1e0->pathBlendWeight =
            -(lbl_803E2548 * lbl_803DC074 - DAT_803de1e0->pathBlendWeight);
        if (DAT_803de1e0->pathBlendWeight < weightFloor)
        {
            DAT_803de1e0->pathBlendWeight = weightFloor;
            DAT_803de1e0->pathBlendStartIndex = target->unkE4;
        }
        startHitVolume = &hitVolumes[DAT_803de1e0->pathBlendStartIndex];
        targetHitVolume = &hitVolumes[target->unkE4];
        startCenterY = startHitVolume->centerY;
        targetCenterY = targetHitVolume->centerY;
        startCenterZ = startHitVolume->centerZ;
        targetCenterZ = targetHitVolume->centerZ;
        weight = DAT_803de1e0->pathBlendWeight;
        *outX = ((startHitVolume->centerX - targetHitVolume->centerX) * weight +
            targetHitVolume->centerX) - focus->anim.worldPosX;
        *outY = ((startCenterY - targetCenterY) * weight + targetCenterY) - *targetY;
        *outZ = ((startCenterZ - targetCenterZ) * weight + targetCenterZ) - focus->anim.worldPosZ;
    }
    DAT_803de1e0->pathBlendTargetIndex = target->unkE4;
}
