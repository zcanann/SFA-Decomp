#include "main/dll/CAM/firstperson.h"
#include "main/camera_interface.h"
#include "main/object_transform.h"


extern undefined4 FUN_800068f4();
extern double FUN_800176f4();
extern undefined4 camcontrol_getTargetPosition();
extern double SeekTwiceBeforeRead();
extern double FUN_80293900();

extern f64 DOUBLE_803e1698;
extern f64 DOUBLE_803e16f8;
extern f32 lbl_803E1710;
extern f32 lbl_803E1714;
extern f64 DOUBLE_803e2318;
extern f64 DOUBLE_803e2378;
extern f32 lbl_803DC074;
extern f32 lbl_803E2314;
extern f32 lbl_803E2324;
extern f32 lbl_803E232C;
extern f32 lbl_803E2380;
extern f32 lbl_803E2384;
extern f32 lbl_803E2388;
extern f32 lbl_803E238C;
extern f32 lbl_803E2390;
extern f32 lbl_803E2394;

#define gCamcontrolModeSettings cameraMtxVar57

static inline f64 FirstPerson_U32AsDouble(u32 value) {
  u64 bits = CONCAT44(0x43300000, value);
  return *(f64 *)&bits;
}

static inline f64 FirstPerson_S32AsDouble(s32 value) {
  u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
  return *(f64 *)&bits;
}

/*
 * --INFO--
 *
 * Function: firstperson_updatePosition
 * EN v1.0 Address: 0x80105178
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: 0x80105338
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 sqrtf();
extern f32 interpolate(f32 delta, f32 rate, f32 dt);
extern f32 PSVECMag(f32 *vec);
extern f32 timeDelta;
extern f32 lbl_803E16AC;
extern f32 lbl_803E1694;
extern f32 lbl_803E16A4;
extern f32 lbl_803E1700;
extern f32 lbl_803E1704;
extern f32 lbl_803E1708;
extern f32 lbl_803E170C;

void firstperson_updatePosition(CameraObject *camera, ObjAnimComponent *target)
{
  f32 dx;
  f32 dz;
  f32 dy;
  f32 dist;
  f32 clamped;
  f32 targetX;
  f32 targetZ;
  f32 ratio;
  f32 speed;

  ((void (*)(int, f32 *, f32 *, f32 *, f32 *, int, f32))(*gCameraInterface)->getRelativePosition)((int)camera, &dx, &dz, &dy, &dist, 1, gCamcontrolModeSettings->targetHeight);
  dist = dy * dy + (dx * dx + dz * dz);
  if (dist > lbl_803E16AC) {
    dist = sqrtf(dist);
  }
  if (dist < lbl_803E1694) {
    dist = lbl_803E1694;
  }
  if (dist > lbl_803E1700 * gCamcontrolModeSettings->maxDistance) {
    camcontrol_getTargetPosition((int)camera, target, &camera->anim.worldPosX, &camera->anim.rotY);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX,camera->anim.worldPosY,camera->anim.worldPosZ,
                                   &camera->anim.localPosX,&camera->anim.localPosY,
                                   &camera->anim.localPosZ,(u32)camera->anim.parent);
    camera->probePosX = camera->anim.worldPosX;
    camera->probePosY = camera->anim.worldPosY;
    camera->probePosZ = camera->anim.worldPosZ;
    (*gCameraInterface)->getRelativePosition(gCamcontrolModeSettings->targetHeight, (int)camera, &dx,
                                             &dz, &dy, &dist, 1);
    dist = dy * dy + (dx * dx + dz * dz);
    if (dist > lbl_803E16AC) {
      dist = sqrtf(dist);
    }
    if (dist < lbl_803E1694) {
      dist = lbl_803E1694;
    }
  }

  if (dist > gCamcontrolModeSettings->maxDistance) {
    clamped = gCamcontrolModeSettings->maxDistance;
    gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
    gCamcontrolModeSettings->clampFlags.b7 = 1;
  }
  else if (dist < gCamcontrolModeSettings->minDistance) {
    clamped = gCamcontrolModeSettings->minDistance;
    gCamcontrolModeSettings->clampFlags.b7 = 0;
  }
  else {
    clamped = dist;
    gCamcontrolModeSettings->clampFlags.b7 = 0;
  }

  targetX = camera->anim.localPosX;
  targetZ = camera->anim.localPosZ;
  if ((gCamcontrolModeSettings->wallAvoidanceFlags.b7 == 0) && (clamped != dist) &&
      (lbl_803E16AC != gCamcontrolModeSettings->distanceAdjustRate)) {
    if (dist < lbl_803E16A4) {
      dist = lbl_803E16A4;
    }
    ratio = interpolate(dist - clamped, gCamcontrolModeSettings->distanceAdjustRate, timeDelta);
    ratio = (dist + ratio) / dist;
    if (ratio > lbl_803E16AC) {
      targetX = target->localPosX + dx / ratio;
      targetZ = target->localPosZ + dy / ratio;
    }
  }

  dx = targetX - camera->anim.localPosX;
  dy = targetZ - camera->anim.localPosZ;
  dist = sqrtf(dx * dx + dy * dy);
  if (dist > lbl_803E16AC) {
    dx = dx / dist;
    dy = dy / dist;
  }
  speed = PSVECMag(&target->velocityX) * (lbl_803E1704 * timeDelta);
  if (speed < lbl_803E16A4) {
    speed = lbl_803E16A4;
  }
  dist = dist < lbl_803E16AC ? lbl_803E16AC : (dist > speed ? speed : dist);
  dist = dist < lbl_803E16AC ? lbl_803E16AC : (dist > lbl_803E1708 ? lbl_803E1708 : dist);
  camera->anim.localPosX = dx * dist + camera->anim.localPosX;
  camera->anim.localPosZ = dy * dist + camera->anim.localPosZ;

  if (gCamcontrolModeSettings->upperHeightOffset > gCamcontrolModeSettings->baseUpperHeightOffset) {
    dx = camera->anim.localPosX - target->localPosX;
    dy = camera->anim.localPosZ - target->localPosZ;
    dist = sqrtf(dx * dx + dy * dy);
    if (dist < lbl_803E170C * gCamcontrolModeSettings->minDistance) {
      if (dist > lbl_803E16AC) {
        dx = dx / dist;
        dy = dy / dist;
      }
      dist = lbl_803E170C * gCamcontrolModeSettings->minDistance;
      camera->anim.localPosX = dist * dx + target->localPosX;
      camera->anim.localPosZ = dist * dy + target->localPosZ;
    }
  }
}

/*
 * --INFO--
 *
 * Function: firstperson_loadSettings
 * EN v1.0 Address: 0x801056C0
 * EN v1.0 Size: 812b
 * EN v1.1 Address: 0x801057AC
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstperson_loadSettings(CamcontrolFirstPersonActionSettings *settings)
{
  float fVar1;
  CameraObject *camera;

  camera = (CameraObject *)(*gCameraInterface)->getCamera();
  gCamcontrolModeSettings->savedTargetHeight = gCamcontrolModeSettings->targetHeight;
  gCamcontrolModeSettings->savedLowerHeightOffset = gCamcontrolModeSettings->lowerHeightOffset;
  gCamcontrolModeSettings->savedUpperHeightOffset = gCamcontrolModeSettings->upperHeightOffset;
  gCamcontrolModeSettings->savedMinDistance = gCamcontrolModeSettings->minDistance;
  gCamcontrolModeSettings->savedMaxDistance = gCamcontrolModeSettings->maxDistance;
  gCamcontrolModeSettings->savedFov = camera->fov;
  gCamcontrolModeSettings->savedSlideRightAmount = gCamcontrolModeSettings->slideRightAmount;
  gCamcontrolModeSettings->savedSlideLeftAmount = gCamcontrolModeSettings->slideLeftAmount;
  gCamcontrolModeSettings->savedHeightAdjustRate = gCamcontrolModeSettings->heightAdjustRate;
  gCamcontrolModeSettings->savedDistanceAdjustRate = gCamcontrolModeSettings->distanceAdjustRate;
  fVar1 = (f32)settings->targetHeight;
  gCamcontrolModeSettings->targetHeight = fVar1;
  gCamcontrolModeSettings->targetTargetHeight = fVar1;
  fVar1 = (f32)(u32)settings->lowerHeightOffset;
  gCamcontrolModeSettings->lowerHeightOffset = fVar1;
  gCamcontrolModeSettings->baseLowerHeightOffset = fVar1;
  gCamcontrolModeSettings->targetLowerHeightOffset = fVar1;
  fVar1 = (f32)(u32)settings->upperHeightOffset;
  gCamcontrolModeSettings->upperHeightOffset = fVar1;
  gCamcontrolModeSettings->baseUpperHeightOffset = fVar1;
  gCamcontrolModeSettings->targetUpperHeightOffset = fVar1;
  fVar1 = (f32)(u32)settings->minDistance;
  gCamcontrolModeSettings->minDistance = fVar1;
  gCamcontrolModeSettings->targetMinDistance = fVar1;
  fVar1 = (f32)(u32)settings->maxDistance;
  gCamcontrolModeSettings->maxDistance = fVar1;
  gCamcontrolModeSettings->targetMaxDistance = fVar1;
  fVar1 = (f32)settings->fov;
  camera->fov = fVar1;
  gCamcontrolModeSettings->fov = fVar1;
  fVar1 = (f32)(u32)settings->slideRightAmount;
  gCamcontrolModeSettings->slideRightAmount = fVar1;
  gCamcontrolModeSettings->targetSlideRightAmount = fVar1;
  fVar1 = (f32)(u32)settings->slideLeftAmount;
  gCamcontrolModeSettings->slideLeftAmount = fVar1;
  gCamcontrolModeSettings->targetSlideLeftAmount = fVar1;
  if (settings->distanceAdjustRate == 0) {
    gCamcontrolModeSettings->targetDistanceAdjustRate = lbl_803E1714;
  }
  else {
    fVar1 = (f32)(u32)settings->distanceAdjustRate / lbl_803E1710;
    gCamcontrolModeSettings->distanceAdjustRate = fVar1;
    gCamcontrolModeSettings->targetDistanceAdjustRate = fVar1;
  }
  if (settings->heightAdjustRate == 0) {
    gCamcontrolModeSettings->targetHeightAdjustRate = lbl_803E1714;
  }
  else {
    fVar1 = (f32)(u32)settings->heightAdjustRate / lbl_803E1710;
    gCamcontrolModeSettings->heightAdjustRate = fVar1;
    gCamcontrolModeSettings->targetHeightAdjustRate = fVar1;
  }
  gCamcontrolModeSettings->transitionTimer = 0;
  gCamcontrolModeSettings->transitionDuration = 0;
}

void CameraModeNormal_free(CameraObject *camera)
{
  cameraMtxVar57->savedWorldX = camera->anim.worldPosX;
  cameraMtxVar57->savedWorldY = camera->anim.worldPosY;
  cameraMtxVar57->savedWorldZ = camera->anim.worldPosZ;
  cameraMtxVar57->savedRotX = camera->anim.rotX;
  cameraMtxVar57->savedRotY = camera->anim.rotY;
  cameraMtxVar57->savedRotZ = camera->anim.rotZ;
  cameraMtxVar57->wallAvoidanceFlags.b6 = 0;
}
