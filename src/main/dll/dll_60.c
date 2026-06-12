#include "main/dll/CAM/dll_60.h"
#include "main/dll/CAM/camcombat_state.h"
#include "main/game_object.h"

extern CameraModeCombatState* DAT_803de1e0;
extern f32 lbl_803DC074;
extern f32 lbl_803E2540;
extern f32 lbl_803E2544;
extern f32 lbl_803E2548;

void camdrakor_computeTargetOffset
(CameraObject* camera, float* outX, float* outY, float* outZ, float* targetY)
{
    float fVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    float fVar5;
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
    fVar1 = lbl_803E2544;
    if (DAT_803de1e0->pathBlendWeight <= lbl_803E2544)
    {
        *outX = hitVolumes[target->unkE4].centerX - focus->anim.worldPosX;
        *outY = hitVolumes[target->unkE4].centerY - *targetY;
        *outZ = hitVolumes[target->unkE4].centerZ - focus->anim.worldPosZ;
    }
    else
    {
        DAT_803de1e0->pathBlendWeight =
            -(lbl_803E2548 * lbl_803DC074 - DAT_803de1e0->pathBlendWeight);
        if (DAT_803de1e0->pathBlendWeight < fVar1)
        {
            DAT_803de1e0->pathBlendWeight = fVar1;
            DAT_803de1e0->pathBlendStartIndex = target->unkE4;
        }
        startHitVolume = &hitVolumes[DAT_803de1e0->pathBlendStartIndex];
        targetHitVolume = &hitVolumes[target->unkE4];
        fVar1 = startHitVolume->centerY;
        fVar2 = targetHitVolume->centerY;
        fVar3 = startHitVolume->centerZ;
        fVar4 = targetHitVolume->centerZ;
        fVar5 = DAT_803de1e0->pathBlendWeight;
        *outX = ((startHitVolume->centerX - targetHitVolume->centerX) * fVar5 +
            targetHitVolume->centerX) - focus->anim.worldPosX;
        *outY = ((fVar1 - fVar2) * fVar5 + fVar2) - *targetY;
        *outZ = ((fVar3 - fVar4) * fVar5 + fVar4) - focus->anim.worldPosZ;
    }
    DAT_803de1e0->pathBlendTargetIndex = target->unkE4;
    return;
}
