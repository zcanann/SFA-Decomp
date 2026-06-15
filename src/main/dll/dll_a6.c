#include "main/dll/dll_A6.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/object_transform.h"

extern f32 lbl_803E1628;

extern void objRenderFn_8003b8f4(GameObject *reticle, undefined4 a, undefined4 b, undefined4 c,
                        undefined4 d, f32 f);

#pragma scheduling off
#pragma peephole off

void camcontrol_updateTargetReticle(CamcontrolTargetObject *fallbackTarget, int unused2,
                                    undefined4 arg3, undefined4 arg4,
                                    undefined4 arg5, undefined4 arg6)
{
  int savedReticleState;
  u8 savedReticleAlpha;
  GameObject *reticle;
  GameObject *targetObject;
  CamcontrolTargetObject *target;
  ObjHitVolumeRuntimeTransform *slot;
  ObjAnimBank *activeBank;
  u8 idx;
  int mode;
  int paletteIdx;
  u16 *flagsObj;

  reticle = (GameObject *)gCamcontrolTargetReticle;
  target = fallbackTarget;
  if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0) {
    target = (CamcontrolTargetObject *)CAMCONTROL_CAMERA->targetReticleOverride;
    savedReticleState = gCamcontrolTargetState;
    gCamcontrolTargetState = 3;
    savedReticleAlpha = reticle->anim.alpha;
    reticle->anim.alpha = 0xFF;
  }

  if (target != NULL) {
    targetObject = (GameObject *)target;
    if (targetObject->anim.hitVolumeTransforms == NULL) goto end;

    idx = target->targetSetupIndex;
    slot = &targetObject->anim.hitVolumeTransforms[idx];

    switch (targetObject->anim.hitVolumeBounds[idx].flags & 0xF) {
    case 1:
      mode = 0;
      break;
    case 4:
    case 9:
      mode = 2;
      break;
    default:
      mode = 1;
      break;
    }

    paletteIdx = (int)target->targetPaletteIndex;
    if (paletteIdx >= 4) paletteIdx = 0;
    gCamcontrolTargetHelpTextId = targetObject->anim.modelInstance->helpTextIds[paletteIdx];

    reticle->anim.worldPosX = slot->jointX;
    reticle->anim.worldPosY = slot->jointY;
    reticle->anim.worldPosZ = slot->jointZ;
    reticle->anim.bankIndex = mode;

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
    objRenderFn_8003b8f4(reticle, arg3, arg4, arg5, arg6, gCamcontrolNormalizedMax);
  } else {
    reticle->anim.parent = NULL;
  }

  activeBank = reticle->anim.banks[reticle->anim.bankIndex];
  flagsObj = (u16 *)activeBank;
  *(u16 *)((u8 *)flagsObj + 0x18) = (u16)(*(u16 *)((u8 *)flagsObj + 0x18) & ~8);

  if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0) {
    gCamcontrolTargetState = (s8)savedReticleState;
    reticle->anim.alpha = savedReticleAlpha;
  }
end:
  ;
}
