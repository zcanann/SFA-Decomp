/*
 * dll_a6 - the camera target-reticle renderer (part of the CAM/camcontrol
 * subsystem; see dll_0001_camcontrol.h).
 *
 * camcontrol_updateTargetReticle() positions and draws the lock-on / A-button
 * reticle each frame. It picks the reticle bank (mode 0/1/2) from the chosen
 * target's hit-volume kind, copies the target hit-volume joint world position
 * onto the reticle object (transforming into the parent's local space when the
 * reticle is parented), publishes the target's help-text id, then renders.
 *
 * When the camera has a targetReticleOverride set, the override target is used
 * instead of the caller-supplied fallback, the reticle is forced fully opaque,
 * and the target state / alpha are saved and restored around the draw.
 */
#include "main/dll/dll_A6.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern f32 lbl_803E1628; /* reticle rootMotionScale constant */

extern void objRenderModelAndHitVolumes(GameObject *reticle, u32 a, u32 b, u32 c,
                                 u32 d, f32 f);

#define RETICLE_BANK_LOCKON 0
#define RETICLE_BANK_DEFAULT 1
#define RETICLE_BANK_CONTEXT 2

void camcontrol_updateTargetReticle(CamcontrolTargetObject *fallbackTarget, int unused2,
                                    u32 arg3, u32 arg4,
                                    u32 arg5, u32 arg6)
{
    int savedReticleState;
    u8 savedReticleAlpha;
    GameObject *reticle;
    GameObject *targetObject;
    CamcontrolTargetObject *target;
    ObjHitVolumeRuntimeTransform *slot;
    ObjAnimBank *activeBank;
    u8 idx;
    int bank;
    int paletteIdx;

    reticle = (GameObject *)gCamcontrolTargetReticle;
    target = fallbackTarget;
    if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0) {
        target = (CamcontrolTargetObject *)CAMCONTROL_CAMERA->targetReticleOverride;
        savedReticleState = gCamcontrolTargetState;
        gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE;
        savedReticleAlpha = reticle->anim.alpha;
        reticle->anim.alpha = 0xFF;
    }

    if (target != NULL) {
        targetObject = (GameObject *)target;
        if (targetObject->anim.hitVolumeTransforms == NULL) goto end;

        idx = target->targetSetupIndex;
        slot = &targetObject->anim.hitVolumeTransforms[idx];

        switch (targetObject->anim.hitVolumeBounds[idx].flags & CAMCONTROL_TARGET_KIND_MASK) {
        case CAMCONTROL_TARGET_KIND_LOCKON:
            bank = RETICLE_BANK_LOCKON;
            break;
        case CAMCONTROL_TARGET_KIND_CONTEXT_A:
        case CAMCONTROL_TARGET_KIND_CONTEXT_B:
            bank = RETICLE_BANK_CONTEXT;
            break;
        default:
            bank = RETICLE_BANK_DEFAULT;
            break;
        }

        paletteIdx = target->targetPaletteIndex;
        if (paletteIdx >= 4) paletteIdx = 0;
        gCamcontrolTargetHelpTextId = targetObject->anim.modelInstance->helpTextIds[paletteIdx];

        reticle->anim.worldPosX = slot->jointX;
        reticle->anim.worldPosY = slot->jointY;
        reticle->anim.worldPosZ = slot->jointZ;
        reticle->anim.bankIndex = bank;

        reticle->anim.parent = targetObject->anim.parent;
        if (reticle->anim.parent != NULL) {
            Obj_TransformWorldPointToLocal(reticle->anim.worldPosX,
                                           reticle->anim.worldPosY,
                                           reticle->anim.worldPosZ,
                                           &reticle->anim.localPosX, &reticle->anim.localPosY,
                                           &reticle->anim.localPosZ,
                                           (u32)reticle->anim.parent);
        } else {
            reticle->anim.localPosX = reticle->anim.worldPosX;
            reticle->anim.localPosY = reticle->anim.worldPosY;
            reticle->anim.localPosZ = reticle->anim.worldPosZ;
        }
        reticle->anim.rotY = 0;
        reticle->anim.rotZ = 0;
        reticle->anim.rootMotionScale = lbl_803E1628;
        ((u8 *)reticle)[0x37] = reticle->anim.alpha;
        objRenderModelAndHitVolumes(reticle, arg3, arg4, arg5, arg6, gCamcontrolNormalizedMax);
    } else {
        reticle->anim.parent = NULL;
    }

    activeBank = reticle->anim.banks[reticle->anim.bankIndex];
    *(u16 *)((u8 *)activeBank + 0x18) = (u16)(*(u16 *)((u8 *)activeBank + 0x18) & ~8);

    if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0) {
        gCamcontrolTargetState = savedReticleState;
        reticle->anim.alpha = savedReticleAlpha;
    }
end:
    ;
}
