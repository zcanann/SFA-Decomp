#include "main/dll/dll_A6.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/object_transform.h"

extern f32 lbl_803E1628;

extern void objRenderFn_8003b8f4(u8 *reticle, undefined4 a, undefined4 b, undefined4 c,
                        undefined4 d, f32 f);

#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: camcontrol_updateTargetReticle
 * EN v1.0 Address: 0x80100AA4
 * EN v1.0 Size: 492b
 */
void camcontrol_updateTargetReticle(CamcontrolTargetObject *fallbackTarget, int unused2,
                                    undefined4 arg3, undefined4 arg4,
                                    undefined4 arg5, undefined4 arg6)
{
  int savedReticleState;
  u8 savedReticleAlpha;
  u8 *reticle;
  CamcontrolTargetObject *target;
  ObjHitVolumeRuntimeBounds *bounds;
  ObjHitVolumeRuntimeTransform *slot;
  u8 idx;
  int mode;
  int paletteIdx;
  u16 *flagsObj;

  reticle = (u8 *)gCamcontrolTargetReticle;
  target = fallbackTarget;
  if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0) {
    target = (CamcontrolTargetObject *)CAMCONTROL_CAMERA->targetReticleOverride;
    savedReticleState = gCamcontrolTargetState;
    gCamcontrolTargetState = 3;
    savedReticleAlpha = ((GameObject *)reticle)->anim.alpha;
    ((GameObject *)reticle)->anim.alpha = 0xFF;
  }

  if (target != NULL) {
    if (((GameObject *)target)->anim.hitVolumeTransforms == NULL) goto end;

    idx = target->targetSetupIndex;
    slot = &((GameObject *)target)->anim.hitVolumeTransforms[idx];
    bounds = &((GameObject *)target)->anim.hitVolumeBounds[idx];

    switch (bounds->flags & 0xF) {
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
    gCamcontrolTargetHelpTextId =
        ((GameObject *)target)->anim.modelInstance->helpTextIds[paletteIdx];

    *(f32 *)(reticle + 0x18) = slot->jointX;
    *(f32 *)(reticle + 0x1C) = slot->jointY;
    *(f32 *)(reticle + 0x20) = slot->jointZ;
    *(s8 *)(reticle + 0xAD) = mode;

    *(u32 *)(reticle + 0x30) = *(u32 *)&((GameObject *)target)->anim.parent;
    if (*(u32 *)(reticle + 0x30) != 0) {
      Obj_TransformWorldPointToLocal(*(f32 *)(reticle + 0x18),
                                     *(f32 *)(reticle + 0x1C),
                                     *(f32 *)(reticle + 0x20),
                                     (f32 *)(reticle + 0xC), (f32 *)(reticle + 0x10),
                                     (f32 *)(reticle + 0x14),
                                     *(u32 *)(reticle + 0x30));
    } else {
      *(f32 *)(reticle + 0xC) = *(f32 *)(reticle + 0x18);
      *(f32 *)(reticle + 0x10) = *(f32 *)(reticle + 0x1C);
      *(f32 *)(reticle + 0x14) = *(f32 *)(reticle + 0x20);
    }
    *(s16 *)(reticle + 0x2) = 0;
    *(s16 *)(reticle + 0x4) = 0;
    *(f32 *)(reticle + 0x8) = lbl_803E1628;
    reticle[0x37] = ((GameObject *)reticle)->anim.alpha;
    objRenderFn_8003b8f4(reticle, arg3, arg4, arg5, arg6, gCamcontrolNormalizedMax);
  } else {
    *(u32 *)(reticle + 0x30) = 0;
  }

  flagsObj = *(u16 **)((u8 *)*(u32 *)(reticle + 0x7C) + (s8)reticle[0xAD] * 4);
  *(u16 *)((u8 *)flagsObj + 0x18) = (u16)(*(u16 *)((u8 *)flagsObj + 0x18) & ~8);

  if ((u32)CAMCONTROL_CAMERA->targetReticleOverride != 0) {
    gCamcontrolTargetState = (s8)savedReticleState;
    ((GameObject *)reticle)->anim.alpha = savedReticleAlpha;
  }
end:
  ;
}
