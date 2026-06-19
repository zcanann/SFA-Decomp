/*
 * dll_BB - per-frame camera commit + queued-action blending.
 *
 * camcontrol_applyState pushes the camcontrol working state onto the live
 * view slot each frame: it sets view orientation, optionally smooth-follows
 * the world position (smoothingFlags bit 7) toward the target, drives the
 * queued-action blend (eased by blendCurveMode: 2 = cubic, 1 = quadratic,
 * else linear) across position/orientation/FOV, then steps the letterbox
 * viewport offset toward its target.
 *
 * camcontrol_applyQueuedAction arms a pending queued action: it builds the
 * blend step from the requested frame count, snapshots the current view as
 * the blend start (or copies it straight through when no blend), records the
 * active action, and hands off to camcontrol_activateHandler.
 *
 * The Camera_func* setters poke the camera target/frame flag bytes and the
 * letterbox target; CAMCONTROL_CAMERA is the global working state.
 *
 * EN v1.0: camcontrol_applyState 0x80101980, camcontrol_applyQueuedAction 0x80101EBC.
 */
#include "main/dll/dll_BB.h"
#include "main/camera.h"
#include "main/gameplay_runtime.h"
extern void Obj_UpdateWorldTransform(s16* obj);
extern void Camera_SetCurrentViewIndex(int index);
extern void Camera_UpdateViewMatrices(void);
extern s16 Camera_GetViewportYOffset(void);
extern void Camera_SetFovY(f32 fovY);
extern f32 interpolate(f32 a, f32 t, f32 exp);
extern void loadMapForCameraPos(f32 x,f32 y,f32 z);
extern void OSReport(const char* msg, ...);
extern void PSVECSubtract(f32 *a,f32 *b,f32 *out);
extern void PSVECNormalize(f32 *src,f32 *dst);
extern f32 PSVECMag(f32 *v);
extern f32 Camera_GetFovY(void);
extern void Camera_SetViewportYOffset(s16 yOffset);
extern s16 lbl_803DD4C0;
extern char sDllBBTimeDebugFormat;
extern f32 timeDelta;
extern f32 lbl_803DD4D0;
extern f32 lbl_803E1668;
extern f32 lbl_803E166C;

void camcontrol_applyState(CamcontrolCameraState *camera)
{
  f32 prog;
  f32 clamped;
  CameraViewSlot *view;
  int itmp;
  f32 mag;
  f32 blendFactor;
  f32 delta[3];

  Camera_SetCurrentViewIndex(0);
  view = Camera_GetCurrentViewSlot();
  view->yaw = camera->yaw;
  view->pitch = camera->pitch;
  view->roll = camera->roll;
  if (((camera->smoothingFlags >> 7) & 1) != 0u) {
    PSVECSubtract(&camera->worldX,&view->x,delta);
    mag = PSVECMag(delta);
    if (mag > gCamcontrolNormalizedMin) {
      PSVECNormalize(delta,delta);
    }
    blendFactor = interpolate(mag,lbl_803E1668,timeDelta);
    mag = (blendFactor < gCamcontrolNormalizedMin) ? gCamcontrolNormalizedMin : ((blendFactor > lbl_803E166C * timeDelta) ? lbl_803E166C * timeDelta : blendFactor);
    view->x = mag * delta[0] + view->x;
    view->y = mag * delta[1] + view->y;
    view->z = mag * delta[2] + view->z;
  }
  else {
    view->x = camera->worldX;
    view->y = camera->worldY;
    view->z = camera->worldZ;
  }
  lbl_803DD4D0 = camera->fovY;
  if (camera->blendProgress > gCamcontrolNormalizedMin) {
    camera->blendProgress = -(camera->blendStep * timeDelta - camera->blendProgress);
    prog = camera->blendProgress;
    clamped = gCamcontrolNormalizedMin;
    clamped = (prog < clamped) ? clamped : ((prog > gCamcontrolNormalizedMax) ? gCamcontrolNormalizedMax : prog);
    camera->blendProgress = clamped;
    if (CAMCONTROL_CAMERA->blendCurveMode == 2) {
      mag = gCamcontrolNormalizedMax - camera->blendProgress * camera->blendProgress * camera->blendProgress;
    }
    else if (CAMCONTROL_CAMERA->blendCurveMode == 1) {
      mag = gCamcontrolNormalizedMax - camera->blendProgress * camera->blendProgress;
    }
    else {
      mag = gCamcontrolNormalizedMax - camera->blendProgress;
    }
    blendFactor = (mag < gCamcontrolNormalizedMin) ? gCamcontrolNormalizedMin : ((mag > gCamcontrolNormalizedMax) ? gCamcontrolNormalizedMax : mag);
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_X) != 0) {
      view->x = blendFactor * (view->x - camera->blendStartX) + camera->blendStartX;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_Y) != 0) {
      view->y = blendFactor * (view->y - camera->blendStartY) + camera->blendStartY;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_Z) != 0) {
      view->z = blendFactor * (view->z - camera->blendStartZ) + camera->blendStartZ;
    }
    OSReport(&sDllBBTimeDebugFormat,blendFactor);
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_YAW) != 0) {
      camera->blendDeltaYaw = camera->blendStartYaw - (u16)view->yaw;
      if (0x8000 < camera->blendDeltaYaw) {
        camera->blendDeltaYaw = (camera->blendDeltaYaw - 0x10000) + 1;
      }
      if (camera->blendDeltaYaw < -0x8000) {
        camera->blendDeltaYaw = (camera->blendDeltaYaw + 0x10000) - 1;
      }
      itmp = (int)((f32)camera->blendDeltaYaw * blendFactor);
      view->yaw = camera->blendStartYaw - itmp;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_PITCH) != 0) {
      camera->blendDeltaPitch = camera->blendStartPitch - (u16)view->pitch;
      if (0x8000 < camera->blendDeltaPitch) {
        camera->blendDeltaPitch = (camera->blendDeltaPitch - 0x10000) + 1;
      }
      if (camera->blendDeltaPitch < -0x8000) {
        camera->blendDeltaPitch = (camera->blendDeltaPitch + 0x10000) - 1;
      }
      itmp = (int)((f32)camera->blendDeltaPitch * blendFactor);
      view->pitch = camera->blendStartPitch - itmp;
    }
    if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_ROLL) != 0) {
      camera->blendDeltaRoll = camera->blendStartRoll - (u16)view->roll;
      if (0x8000 < camera->blendDeltaRoll) {
        camera->blendDeltaRoll = (camera->blendDeltaRoll - 0x10000) + 1;
      }
      if (camera->blendDeltaRoll < -0x8000) {
        camera->blendDeltaRoll = (camera->blendDeltaRoll + 0x10000) - 1;
      }
      itmp = (int)((f32)camera->blendDeltaRoll * blendFactor);
      view->roll = camera->blendStartRoll - itmp;
    }
  }
  Camera_SetFovY(lbl_803DD4D0);
  Obj_UpdateWorldTransform((s16 *)view);
  loadMapForCameraPos(camera->worldX,camera->worldY,camera->worldZ);
  itmp = Camera_GetViewportYOffset();
  lbl_803DD4C0 = itmp;
  if ((int)lbl_803DD4C0 != camera->letterboxTargetOffset) {
    if ((int)lbl_803DD4C0 < camera->letterboxTargetOffset) {
      lbl_803DD4C0 = lbl_803DD4C0 + camera->letterboxStep * (int)timeDelta;
      if ((int)lbl_803DD4C0 > camera->letterboxTargetOffset) {
        lbl_803DD4C0 = camera->letterboxTargetOffset;
      }
    }
    else {
      lbl_803DD4C0 = lbl_803DD4C0 - camera->letterboxStep * (int)timeDelta;
      if ((int)lbl_803DD4C0 < camera->letterboxTargetOffset) {
        lbl_803DD4C0 = camera->letterboxTargetOffset;
      }
    }
    Camera_SetViewportYOffset(lbl_803DD4C0);
  }
  camera->letterboxTargetOffset = 0;
  Camera_UpdateViewMatrices();
}

#pragma opt_common_subs off
void camcontrol_applyQueuedAction(void)
{
  CameraViewSlot *view;
  f32 blendStep;

  if (gCamcontrolQueuedActionPending != '\0') {
    if (gCamcontrolQueuedActionBlendFrames > 1) {
      blendStep = gCamcontrolNormalizedMax / gCamcontrolQueuedActionBlendFrames;
      if ((blendStep <= gCamcontrolNormalizedMin) || (blendStep > gCamcontrolNormalizedMax)) {
        blendStep = gCamcontrolNormalizedMax;
      }
      CAMCONTROL_CAMERA->blendProgress = gCamcontrolNormalizedMax;
      CAMCONTROL_CAMERA->blendStep = blendStep;
      CAMCONTROL_CAMERA->queuedBlendFlags = gCamcontrolQueuedActionMode;
    }
    else {
      CAMCONTROL_CAMERA->blendProgress = gCamcontrolNormalizedMin;
      CAMCONTROL_CAMERA->queuedBlendFlags = 0;
    }
    view = Camera_GetCurrentViewSlot();
    if (gCamcontrolNormalizedMax == CAMCONTROL_CAMERA->blendProgress) {
      CAMCONTROL_CAMERA->blendStartX = view->x;
      CAMCONTROL_CAMERA->blendStartY = view->y;
      CAMCONTROL_CAMERA->blendStartZ = view->z;
      CAMCONTROL_CAMERA->blendStartYaw = view->yaw;
      CAMCONTROL_CAMERA->blendStartPitch = view->pitch;
      CAMCONTROL_CAMERA->blendStartRoll = view->roll;
      CAMCONTROL_CAMERA->blendStartFovY = Camera_GetFovY();
    }
    else {
      CAMCONTROL_CAMERA->yaw = view->yaw;
      CAMCONTROL_CAMERA->pitch = view->pitch;
      CAMCONTROL_CAMERA->roll = view->roll;
      CAMCONTROL_CAMERA->fovY = Camera_GetFovY();
    }
    gCamcontrolSavedActionId = gCamcontrolActiveActionId;
    gCamcontrolSavedActionPriority = gCamcontrolActiveActionPriority;
    gCamcontrolSavedActionStartFlags = gCamcontrolActiveActionStartFlags;
    camcontrol_activateHandler((u16)gCamcontrolQueuedActionId,gCamcontrolQueuedActionData);
    gCamcontrolQueuedActionPending = '\0';
    if (gCamcontrolQueuedActionData != NULL) {
      mm_free(gCamcontrolQueuedActionData);
      gCamcontrolQueuedActionData = NULL;
    }
  }
}
#pragma opt_common_subs reset

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
  if (yOffset > CAMCONTROL_CAMERA->letterboxTargetOffset) {
    CAMCONTROL_CAMERA->letterboxTargetOffset = yOffset;
    CAMCONTROL_CAMERA->letterboxStep = 2;
    if (applyNow != 0) {
      Camera_SetViewportYOffset((s16)yOffset);
    }
  }
}
