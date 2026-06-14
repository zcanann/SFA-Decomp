#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_BB.h"

extern void Obj_UpdateWorldTransform(void *obj);
extern void Camera_SetCurrentViewIndex(s32 index);
extern void Camera_UpdateViewMatrices(void);
extern s32 Camera_GetViewportYOffset(void);
extern void Camera_SetFovY(f32 fovY);
extern f32 interpolate(f32 cur,f32 target,f32 t);
extern void loadMapForCameraPos(f32 x,f32 y,f32 z);
extern void OSReport(const char *fmt,...);
extern void PSVECSubtract(f32 *a,f32 *b,f32 *out);
extern void PSVECNormalize(f32 *src,f32 *dst);
extern f32 PSVECMag(f32 *v);
extern CameraViewSlot *Camera_GetCurrentViewSlot(void);
extern f32 Camera_GetFovY(void);
extern void Camera_SetViewportYOffset(s32 yOffset);
extern void mm_free(void *ptr);

extern s16 lbl_803DD4C0;
extern char sDllBBTimeDebugFormat[];
extern f64 lbl_803E1650;
extern f32 timeDelta;
extern f32 lbl_803DD4D0;
extern f32 lbl_803E1668;
extern f32 lbl_803E166C;

/*
 * --INFO--
 *
 * Function: camcontrol_applyState
 * EN v1.0 Address: 0x80101980
 * EN v1.0 Size: 1332b
 * EN v1.1 Address: 0x80101C1C
 * EN v1.1 Size: 1340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_applyState(CamcontrolCameraState *camera)
{
  float fVar1;
  float fVar2;
  CameraViewSlot *view;
  int iVar4;
  float fVar5;
  float fVar6;
  float delta[3];

  Camera_SetCurrentViewIndex(0);
  view = Camera_GetCurrentViewSlot();
  view->yaw = camera->yaw;
  view->pitch = camera->pitch;
  view->roll = camera->roll;
  if ((camera->smoothingFlags & 0x80) != 0) {
    PSVECSubtract(&camera->localX,&view->x,delta);
    fVar5 = PSVECMag(delta);
    if (fVar5 > gCamcontrolNormalizedMin) {
      PSVECNormalize(delta,delta);
    }
    fVar6 = interpolate(fVar5,lbl_803E1668,timeDelta);
    fVar5 = (fVar6 < gCamcontrolNormalizedMin) ? gCamcontrolNormalizedMin : ((fVar6 > lbl_803E166C * timeDelta) ? lbl_803E166C * timeDelta : fVar6);
    view->x = fVar5 * delta[0] + view->x;
    view->y = fVar5 * delta[1] + view->y;
    view->z = fVar5 * delta[2] + view->z;
  }
  else {
    view->x = camera->localX;
    view->y = camera->localY;
    view->z = camera->localZ;
  }
  fVar2 = gCamcontrolNormalizedMin;
  lbl_803DD4D0 = camera->fovY;
  if (gCamcontrolNormalizedMin < camera->blendProgress) {
    camera->blendProgress = -(camera->blendStep * timeDelta - camera->blendProgress);
    fVar1 = camera->blendProgress;
    fVar2 = (fVar1 < fVar2) ? fVar2 : ((fVar1 > gCamcontrolNormalizedMax) ? gCamcontrolNormalizedMax : fVar1);
    camera->blendProgress = fVar2;
    if (camera->blendCurveMode == 2) {
      fVar2 = camera->blendProgress;
      fVar5 = gCamcontrolNormalizedMax - fVar2 * fVar2 * fVar2;
    }
    else if (camera->blendCurveMode == 1) {
      fVar5 = gCamcontrolNormalizedMax - camera->blendProgress * camera->blendProgress;
    }
    else {
      fVar5 = gCamcontrolNormalizedMax - camera->blendProgress;
    }
    fVar6 = (fVar5 < gCamcontrolNormalizedMin) ? gCamcontrolNormalizedMin : ((fVar5 > gCamcontrolNormalizedMax) ? gCamcontrolNormalizedMax : fVar5);
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_X) != 0) {
      view->x = fVar6 * (view->x - camera->blendStartX) + camera->blendStartX;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_Y) != 0) {
      view->y = fVar6 * (view->y - camera->blendStartY) + camera->blendStartY;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_Z) != 0) {
      view->z = fVar6 * (view->z - camera->blendStartZ) + camera->blendStartZ;
    }
    OSReport(sDllBBTimeDebugFormat,fVar6);
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_YAW) != 0) {
      camera->blendDeltaYaw = camera->blendStartYaw - view->yaw;
      if (0x8000 < camera->blendDeltaYaw) {
        camera->blendDeltaYaw = camera->blendDeltaYaw + 1;
      }
      if (camera->blendDeltaYaw < -0x8000) {
        camera->blendDeltaYaw = camera->blendDeltaYaw + -1;
      }
      iVar4 = (int)((float)camera->blendDeltaYaw * fVar6);
      view->yaw = camera->blendStartYaw - (short)iVar4;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_PITCH) != 0) {
      camera->blendDeltaPitch = camera->blendStartPitch - view->pitch;
      if (0x8000 < camera->blendDeltaPitch) {
        camera->blendDeltaPitch = camera->blendDeltaPitch + 1;
      }
      if (camera->blendDeltaPitch < -0x8000) {
        camera->blendDeltaPitch = camera->blendDeltaPitch + -1;
      }
      iVar4 = (int)((float)camera->blendDeltaPitch * fVar6);
      view->pitch = camera->blendStartPitch - (short)iVar4;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_ROLL) != 0) {
      camera->blendDeltaRoll = camera->blendStartRoll - view->roll;
      if (0x8000 < camera->blendDeltaRoll) {
        camera->blendDeltaRoll = camera->blendDeltaRoll + 1;
      }
      if (camera->blendDeltaRoll < -0x8000) {
        camera->blendDeltaRoll = camera->blendDeltaRoll + -1;
      }
      iVar4 = (int)((float)camera->blendDeltaRoll * fVar6);
      view->roll = camera->blendStartRoll - (short)iVar4;
    }
  }
  Camera_SetFovY(lbl_803DD4D0);
  Obj_UpdateWorldTransform(view);
  loadMapForCameraPos(camera->localX,camera->localY,camera->localZ);
  iVar4 = Camera_GetViewportYOffset();
  lbl_803DD4C0 = (short)iVar4;
  if ((int)lbl_803DD4C0 != (int)camera->letterboxTargetOffset) {
    if ((int)lbl_803DD4C0 < (int)camera->letterboxTargetOffset) {
      lbl_803DD4C0 = lbl_803DD4C0 + (short)camera->letterboxStep * (short)(int)timeDelta;
      if ((int)camera->letterboxTargetOffset < (int)lbl_803DD4C0) {
        lbl_803DD4C0 = (short)camera->letterboxTargetOffset;
      }
    }
    else {
      lbl_803DD4C0 = lbl_803DD4C0 - (short)camera->letterboxStep * (short)(int)timeDelta;
      if ((int)lbl_803DD4C0 < (int)camera->letterboxTargetOffset) {
        lbl_803DD4C0 = (short)camera->letterboxTargetOffset;
      }
    }
    Camera_SetViewportYOffset(lbl_803DD4C0);
  }
  camera->letterboxTargetOffset = 0;
  Camera_UpdateViewMatrices();
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_applyQueuedAction
 * EN v1.0 Address: 0x80101EBC
 * EN v1.0 Size: 400b
 */
void camcontrol_applyQueuedAction(void)
{
  CamcontrolCameraState *camera;
  CameraViewSlot *view;
  float blendStep;

  if (gCamcontrolQueuedActionPending != '\0') {
    camera = CAMCONTROL_CAMERA;
    if (gCamcontrolQueuedActionBlendFrames > 1) {
      blendStep = gCamcontrolNormalizedMax / (float)gCamcontrolQueuedActionBlendFrames;
      if ((blendStep <= gCamcontrolNormalizedMin) || (blendStep > gCamcontrolNormalizedMax)) {
        blendStep = gCamcontrolNormalizedMax;
      }
      camera->blendProgress = gCamcontrolNormalizedMax;
      camera->blendStep = blendStep;
      camera->queuedBlendFlags = gCamcontrolQueuedActionMode;
    }
    else {
      camera->blendProgress = gCamcontrolNormalizedMin;
      camera->queuedBlendFlags = 0;
    }
    view = Camera_GetCurrentViewSlot();
    if (gCamcontrolNormalizedMax == camera->blendProgress) {
      camera->blendStartX = view->x;
      camera->blendStartY = view->y;
      camera->blendStartZ = view->z;
      camera->blendStartYaw = view->yaw;
      camera->blendStartPitch = view->pitch;
      camera->blendStartRoll = view->roll;
      camera->blendStartFovY = Camera_GetFovY();
    }
    else {
      camera->yaw = view->yaw;
      camera->pitch = view->pitch;
      camera->roll = view->roll;
      camera->fovY = Camera_GetFovY();
    }
    gCamcontrolSavedActionId = gCamcontrolActiveActionId;
    gCamcontrolSavedActionPriority = gCamcontrolActiveActionPriority;
    gCamcontrolSavedActionStartFlags = gCamcontrolActiveActionStartFlags;
    camcontrol_activateHandler((u16)gCamcontrolQueuedActionId,gCamcontrolQueuedActionData);
    gCamcontrolQueuedActionPending = '\0';
    if (gCamcontrolQueuedActionData != (void *)0x0) {
      mm_free(gCamcontrolQueuedActionData);
      gCamcontrolQueuedActionData = (void *)0x0;
    }
  }
  return;
}

void Camera_func1D(int targetFlagMode)
{
  CAMCONTROL_CAMERA->targetFlags = (u8)(CAMCONTROL_CAMERA->targetFlags | ((targetFlagMode << 3) & 0x18));
}

void Camera_func13(int enable)
{
  if (enable != 0) {
    CAMCONTROL_CAMERA->targetFlags = (u8)(CAMCONTROL_CAMERA->targetFlags | 2);
  }
  else {
    CAMCONTROL_CAMERA->targetFlags = (u8)(CAMCONTROL_CAMERA->targetFlags & ~2);
  }
}

void Camera_func1C(int flags)
{
  CAMCONTROL_CAMERA->frameFlags = (u8)(CAMCONTROL_CAMERA->frameFlags | flags);
}

void Camera_setLetterbox(int yOffset,int applyNow)
{
  if (yOffset > (int)CAMCONTROL_CAMERA->letterboxTargetOffset) {
    CAMCONTROL_CAMERA->letterboxTargetOffset = yOffset;
    CAMCONTROL_CAMERA->letterboxStep = 2;
    if (applyNow != 0) {
      Camera_SetViewportYOffset((s16)yOffset);
    }
  }
  return;
}
