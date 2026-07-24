/* DLL 0x0049 (cameramodecombat) - path-blend focus offset helper [0x8010BF08-0x8010C064). */
#include "main/camera_interface.h"
#include "main/resource.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/camera.h"
#include "main/dll/CAM/camcombat_state.h"
#include "main/dll/CAM/cutCam.h"
#include "main/mm.h"
#include "main/rcp_dolphin_api.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "main/pad.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/dll/player_api.h"
#include "main/dll/dll_0049_cameramodecombat.h"

extern CameraModeCombatState* gCamCombatState;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
extern f32 lbl_803E18C8;

void fn_8010BF08(CameraObject* camera, float* outX, float* outY, float* outZ, f32* targetY)
{
    GameObject* focus;
    GameObject* target;
    ObjHitVolumeRuntimeTransform* hitVolumes;
    u8 curIdx;
    float lim;
    float t;

    target = (GameObject*)camera->targetObj;
    focus = (GameObject*)camera->anim.targetObj;
    hitVolumes = target->anim.hitVolumeTransforms;
    curIdx = target->hitVolumeIndex;
    if ((u32)curIdx != gCamCombatState->pathBlendTargetIndex)
    {
        gCamCombatState->pathBlendStartIndex = gCamCombatState->pathBlendTargetIndex;
        gCamCombatState->pathBlendWeight = lbl_803E18C0;
    }
    t = gCamCombatState->pathBlendWeight;
    lim = lbl_803E18C4;
    if (t > lim)
    {
        gCamCombatState->pathBlendWeight = t - lbl_803E18C8 * timeDelta;
        t = gCamCombatState->pathBlendWeight;
        if (gCamCombatState->pathBlendWeight < lim)
        {
            gCamCombatState->pathBlendWeight = lim;
            gCamCombatState->pathBlendStartIndex = target->hitVolumeIndex;
        }
        {
            u8 ci = gCamCombatState->pathBlendStartIndex;
            float w;
            float dx = hitVolumes[ci].centerX - hitVolumes[target->hitVolumeIndex].centerX;
            float dy = hitVolumes[ci].centerY - hitVolumes[target->hitVolumeIndex].centerY;
            float dz = hitVolumes[ci].centerZ - hitVolumes[target->hitVolumeIndex].centerZ;
            w = gCamCombatState->pathBlendWeight;
            dx *= w;
            dy *= w;
            dz *= w;
            dx += hitVolumes[target->hitVolumeIndex].centerX;
            dy += hitVolumes[target->hitVolumeIndex].centerY;
            dz += hitVolumes[target->hitVolumeIndex].centerZ;
            *outX = dx - focus->anim.worldPosX;
            *outY = dy - *targetY;
            *outZ = dz - focus->anim.worldPosZ;
        }
    }
    else
    {
        *outX = hitVolumes[target->hitVolumeIndex].centerX - focus->anim.worldPosX;
        *outY = hitVolumes[target->hitVolumeIndex].centerY - *targetY;
        *outZ = hitVolumes[target->hitVolumeIndex].centerZ - focus->anim.worldPosZ;
    }
    gCamCombatState->pathBlendTargetIndex = target->hitVolumeIndex;
}
