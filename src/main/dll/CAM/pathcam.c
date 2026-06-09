#include "main/dll/CAM/pathcam.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "string.h"


#pragma peephole off
#pragma scheduling off
extern int getAngle(f32 dx,f32 dz);
extern undefined4 camcontrol_getTargetPosition();
extern f32 Curve_EvalHermite(f32 param_1, f32 *param_2, f32 *param_3);
extern undefined4 Curve_AdvanceAlongPath(f32 param_1, f32 *param_2);

extern undefined4 lbl_803DD538;
extern f64 DOUBLE_803e1698;
extern f64 DOUBLE_803e16f8;
extern f32 lbl_803E16D0;
extern f32 lbl_803E16D4;
extern f32 lbl_803E16DC;
extern f32 lbl_803E16F0;
extern f32 lbl_803E1710;
extern f32 lbl_803E1714;
extern f32 lbl_803E1734;
extern f32 lbl_803E1738;
extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 lbl_803E1748;

#define gCamcontrolModeSettings cameraMtxVar57
#define gCamcontrolPathState lbl_803DD538

/*
 * --INFO--
 *
 * Function: pathcam_loadSettings
 * EN v1.0 Address: 0x80105E7C
 * EN v1.0 Size: 1900b
 * EN v1.1 Address: 0x80106118
 * EN v1.1 Size: 1904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pathcam_loadSettings(u16 *cam, int mode, u8 *data)
{
    s16 *target;
    f32 vOutA;
    f32 vOutB;
    f32 vOutC;
    f32 vOutD;
    f32 fVal;
    u32 uVal;

    gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
    gCamcontrolModeSettings->collisionState = 0;
    gCamcontrolModeSettings->collisionProbeTimer = 0;
    gCamcontrolModeSettings->wallAvoidanceTimer = 0;
    gCamcontrolModeSettings->clampFlags.b7 = 0;
    gCamcontrolModeSettings->yawResponseFrames = 8;
    target = ((CameraObject *)cam)->anim.targetObj;
    switch (mode) {
    case 0:
        memset(gCamcontrolModeSettings, 0, sizeof(CamcontrolModeSettings));
        if (data != NULL) {
            fVal = (f32)(u32)*(u16 *)(data + 0x1c);
            gCamcontrolModeSettings->minDistance = fVal;
            gCamcontrolModeSettings->targetMinDistance = fVal;
            fVal = (f32)(u32)*(u16 *)(data + 0x1a);
            gCamcontrolModeSettings->maxDistance = fVal;
            gCamcontrolModeSettings->targetMaxDistance = fVal;
            fVal = (f32)(u32)data[0x1f];
            gCamcontrolModeSettings->baseLowerHeightOffset = fVal;
            gCamcontrolModeSettings->lowerHeightOffset = fVal;
            gCamcontrolModeSettings->targetLowerHeightOffset = fVal;
            fVal = (f32)(u32)data[0x1f];
            gCamcontrolModeSettings->baseUpperHeightOffset = fVal;
            gCamcontrolModeSettings->upperHeightOffset = fVal;
            gCamcontrolModeSettings->targetUpperHeightOffset = fVal;
        }
        fVal = lbl_803E16F0;
        gCamcontrolModeSettings->targetHeight = fVal;
        gCamcontrolModeSettings->targetTargetHeight = fVal;
        fVal = lbl_803E1714;
        gCamcontrolModeSettings->distanceAdjustRate = fVal;
        gCamcontrolModeSettings->targetDistanceAdjustRate = fVal;
        fVal = lbl_803E1734;
        gCamcontrolModeSettings->savedHeightAdjustRate = fVal;
        gCamcontrolModeSettings->heightAdjustRate = fVal;
        gCamcontrolModeSettings->targetHeightAdjustRate = fVal;
        fVal = lbl_803E1738;
        gCamcontrolModeSettings->slideRightAmount = fVal;
        gCamcontrolModeSettings->targetSlideRightAmount = fVal;
        fVal = lbl_803E16DC;
        gCamcontrolModeSettings->slideLeftAmount = fVal;
        gCamcontrolModeSettings->targetSlideLeftAmount = fVal;
        gCamcontrolModeSettings->pad24 = lbl_803E16D0;
        gCamcontrolModeSettings->pad20 = lbl_803E16D4;
        gCamcontrolModeSettings->initialized = 1;
        gCamcontrolModeSettings->fov = ((CameraObject *)cam)->fov;
        camcontrol_getTargetPosition((int)cam, target, (f32 *)(cam + 0xc), cam + 1);
        fVal = *(f32 *)(cam + 0xc);
        *(f32 *)(cam + 6) = fVal;
        ((CameraObject *)cam)->probePosX = fVal;
        ((CameraObject *)cam)->anim.hitboxScale = fVal;
        fVal = ((CameraObject *)cam)->anim.worldPosY;
        *(f32 *)(cam + 8) = fVal;
        ((CameraObject *)cam)->probePosY = fVal;
        *(f32 *)(cam + 0x56) = fVal;
        fVal = ((CameraObject *)cam)->anim.worldPosZ;
        *(f32 *)(cam + 10) = fVal;
        ((CameraObject *)cam)->probePosZ = fVal;
        *(f32 *)(cam + 0x58) = fVal;
        cam[0] = 0;
        cam[2] = 0;
        if (data != NULL) {
            ((CameraObject *)cam)->fov = (f32)(u32)data[0x19];
        }
        break;
    case 4:
        camcontrol_getTargetPosition((int)cam, target, (f32 *)(cam + 0xc), cam + 1);
        Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0xc), ((CameraObject *)cam)->anim.worldPosY, ((CameraObject *)cam)->anim.worldPosZ,
                                       (f32 *)(cam + 6), (f32 *)(cam + 8), (f32 *)(cam + 10),
                                       *(int *)(cam + 0x18));
        (*gCameraInterface)->getRelativePosition(gCamcontrolModeSettings->targetHeight, (int)cam,
                                                 &vOutA, &vOutB, &vOutC, &vOutD, 0);
        vOutB = *(f32 *)(cam + 8) - (*(f32 *)(target + 8) + gCamcontrolModeSettings->targetHeight);
        ((s16 *)cam)[1] = getAngle(vOutB, vOutD);
        cam[2] = 0;
        ((CameraObject *)cam)->probePosX = *(f32 *)(cam + 0xc);
        ((CameraObject *)cam)->probePosY = ((CameraObject *)cam)->anim.worldPosY;
        ((CameraObject *)cam)->probePosZ = ((CameraObject *)cam)->anim.worldPosZ;
        ((CameraObject *)cam)->anim.hitboxScale = *(f32 *)(cam + 6);
        *(f32 *)(cam + 0x56) = *(f32 *)(cam + 8);
        *(f32 *)(cam + 0x58) = *(f32 *)(cam + 10);
        ((CameraObject *)cam)->fov = gCamcontrolModeSettings->fov;
        gCamcontrolModeSettings->transitionTimer = 0;
        break;
    case 2:
        if (data != NULL) {
            gCamcontrolModeSettings->targetTargetHeight = lbl_803E16F0;
            fVal = (f32)(u32)data[6];
            gCamcontrolModeSettings->baseLowerHeightOffset = fVal;
            gCamcontrolModeSettings->targetLowerHeightOffset = fVal;
            fVal = (f32)(u32)data[8];
            gCamcontrolModeSettings->baseUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetMinDistance = (f32)(u32)data[3];
            gCamcontrolModeSettings->targetMaxDistance = (f32)(u32)data[4];
            gCamcontrolModeSettings->fov = (f32)*(s8 *)(data + 2);
            gCamcontrolModeSettings->targetSlideRightAmount = (f32)(u32)data[9];
            gCamcontrolModeSettings->targetSlideLeftAmount = (f32)(u32)data[0xa];
            uVal = data[0xb];
            if (uVal != 0) {
                gCamcontrolModeSettings->targetDistanceAdjustRate = (f32)uVal / lbl_803E1710;
            } else {
                gCamcontrolModeSettings->targetDistanceAdjustRate = lbl_803E1714;
            }
            uVal = data[0xc];
            if (uVal != 0) {
                gCamcontrolModeSettings->targetHeightAdjustRate = (f32)uVal / lbl_803E1710;
            } else {
                gCamcontrolModeSettings->targetHeightAdjustRate = lbl_803E1714;
            }
            gCamcontrolModeSettings->transitionTimer = (s16)*(s8 *)(data + 1);
            gCamcontrolModeSettings->transitionDuration = (s16)*(s8 *)(data + 1);
            *((u8 *)cam + 0x13b) = data[7];
        } else {
            gCamcontrolModeSettings->targetTargetHeight = gCamcontrolModeSettings->savedTargetHeight;
            fVal = gCamcontrolModeSettings->savedLowerHeightOffset;
            gCamcontrolModeSettings->baseLowerHeightOffset = fVal;
            gCamcontrolModeSettings->targetLowerHeightOffset = fVal;
            fVal = gCamcontrolModeSettings->savedUpperHeightOffset;
            gCamcontrolModeSettings->baseUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetUpperHeightOffset = fVal;
            gCamcontrolModeSettings->targetMinDistance = gCamcontrolModeSettings->savedMinDistance;
            gCamcontrolModeSettings->targetMaxDistance = gCamcontrolModeSettings->savedMaxDistance;
            gCamcontrolModeSettings->fov = gCamcontrolModeSettings->savedFov;
            gCamcontrolModeSettings->targetSlideRightAmount =
                gCamcontrolModeSettings->savedSlideRightAmount;
            gCamcontrolModeSettings->targetSlideLeftAmount =
                gCamcontrolModeSettings->savedSlideLeftAmount;
            gCamcontrolModeSettings->targetDistanceAdjustRate =
                gCamcontrolModeSettings->savedDistanceAdjustRate;
            gCamcontrolModeSettings->targetHeightAdjustRate =
                gCamcontrolModeSettings->savedHeightAdjustRate;
            gCamcontrolModeSettings->transitionTimer = 0x3c;
            gCamcontrolModeSettings->transitionDuration = 0x3c;
        }
        gCamcontrolModeSettings->savedTargetHeight = gCamcontrolModeSettings->targetHeight;
        gCamcontrolModeSettings->savedLowerHeightOffset = gCamcontrolModeSettings->lowerHeightOffset;
        gCamcontrolModeSettings->savedUpperHeightOffset = gCamcontrolModeSettings->upperHeightOffset;
        gCamcontrolModeSettings->savedMinDistance = gCamcontrolModeSettings->minDistance;
        gCamcontrolModeSettings->savedMaxDistance = gCamcontrolModeSettings->maxDistance;
        gCamcontrolModeSettings->savedFov = ((CameraObject *)cam)->fov;
        gCamcontrolModeSettings->savedSlideRightAmount = gCamcontrolModeSettings->slideRightAmount;
        gCamcontrolModeSettings->savedSlideLeftAmount = gCamcontrolModeSettings->slideLeftAmount;
        gCamcontrolModeSettings->savedDistanceAdjustRate =
            gCamcontrolModeSettings->distanceAdjustRate;
        gCamcontrolModeSettings->savedHeightAdjustRate = gCamcontrolModeSettings->heightAdjustRate;
        if ((data != NULL) && (data[0xd] != 0)) {
            camcontrol_getTargetPosition((int)cam, target, (f32 *)(cam + 0xc), cam + 1);
            Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0xc), ((CameraObject *)cam)->anim.worldPosY, ((CameraObject *)cam)->anim.worldPosZ,
                                           (f32 *)(cam + 6), (f32 *)(cam + 8), (f32 *)(cam + 10),
                                           *(int *)(cam + 0x18));
            gCamcontrolModeSettings->transitionTimer = 0;
        }
        break;
    case 3:
        ((CameraObject *)cam)->fov = gCamcontrolModeSettings->fov;
        *(f32 *)(cam + 0xc) = gCamcontrolModeSettings->savedWorldX;
        ((CameraObject *)cam)->anim.worldPosY = gCamcontrolModeSettings->savedWorldY;
        ((CameraObject *)cam)->anim.worldPosZ = gCamcontrolModeSettings->savedWorldZ;
        Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0xc), ((CameraObject *)cam)->anim.worldPosY, ((CameraObject *)cam)->anim.worldPosZ,
                                       (f32 *)(cam + 6), (f32 *)(cam + 8), (f32 *)(cam + 10),
                                       *(int *)(cam + 0x18));
        ((s16 *)cam)[0] = gCamcontrolModeSettings->savedRotX;
        ((s16 *)cam)[1] = gCamcontrolModeSettings->savedRotY;
        ((s16 *)cam)[2] = gCamcontrolModeSettings->savedRotZ;
        ((CameraObject *)cam)->anim.hitboxScale = *(f32 *)(cam + 6);
        *(f32 *)(cam + 0x56) = *(f32 *)(cam + 8);
        *(f32 *)(cam + 0x58) = *(f32 *)(cam + 10);
        ((CameraObject *)cam)->probePosX = *(f32 *)(cam + 0xc);
        ((CameraObject *)cam)->probePosY = ((CameraObject *)cam)->anim.worldPosY;
        ((CameraObject *)cam)->probePosZ = ((CameraObject *)cam)->anim.worldPosZ;
        gCamcontrolModeSettings->transitionTimer = 0;
        break;
    case 1:
        ((CameraObject *)cam)->fov = gCamcontrolModeSettings->fov;
        gCamcontrolModeSettings->wallAvoidanceFlags.b7 =
            gCamcontrolModeSettings->wallAvoidanceFlags.b6;
        break;
    }
    gCamcontrolModeSettings->wallAvoidanceFlags.b6 = 0;
    *((u8 *)cam + 0x13e) = 1;
}

void camcontrol_releaseModeSettings(void) { mm_free(cameraMtxVar57); cameraMtxVar57 = 0; }

void camcontrol_initialiseModeSettings(void)
{
  cameraMtxVar57 = (CamcontrolModeSettings *)mmAlloc(sizeof(CamcontrolModeSettings),0xf,0);
  memset(cameraMtxVar57,0,sizeof(CamcontrolModeSettings));
  return;
}

void camcontrol_samplePathState(f32 *outX,f32 *height,f32 *outZ,undefined4 param_4,int param_5)
{
  CamcontrolPathSampleWork work;
  int iVar1;
  int iVar2;
  f32 pathT;

  memset(&work,0,0x144);
  work.model = *(int *)(param_5 + 0x30);
  iVar1 = gCamcontrolPathState + *(int *)(gCamcontrolPathState + 0x1b0) * 4;
  work.sampleX = *(float *)(iVar1 + 0x14);
  work.sampleY = *height;
  work.sampleZ = *(float *)(iVar1 + 0xb4);
  work.localX = work.sampleX;
  work.localY = work.sampleY;
  work.localZ = work.sampleZ;
  Obj_TransformLocalPointToWorld((double)work.sampleX,(double)work.sampleY,(double)work.sampleZ,
                                 &work.worldX,&work.worldY,work.worldZ,work.model);
  work.targetObj = param_4;
  iVar1 = (int)(*gCameraInterface)->getDefaultHandlerEntry();
  (*(code *)(**(int **)(iVar1 + 4) + 0x14))(&work,param_4);
  Obj_TransformLocalPointToWorld(work.sampleX,work.sampleY,work.sampleZ,
                                 &work.targetX,&work.targetY,work.targetZ,work.model);
  (*(code *)(**(int **)(iVar1 + 4) + 0x24))
            (&work,1,3,gCamcontrolPathState + 0x14,gCamcontrolPathState + 0x18);
  iVar2 = *(int *)(gCamcontrolPathState + 0x1b0) + -3;
  iVar1 = iVar2 * 4;
  for (; iVar2 < *(int *)(gCamcontrolPathState + 0x1b0); iVar2 = iVar2 + 1) {
    *(float *)(gCamcontrolPathState + iVar1 + 0x1c) = work.sampleX;
    *(float *)(gCamcontrolPathState + iVar1 + 0xbc) = work.sampleZ;
    iVar1 = iVar1 + 4;
  }
  if (lbl_803E1740 != *(float *)(gCamcontrolPathState + 300)) {
    pathT = *(float *)(gCamcontrolPathState + 0x128) /
            *(float *)(gCamcontrolPathState + 300);
  } else {
    pathT = lbl_803E1740;
  }
  if (pathT > lbl_803E1744) {
    pathT = lbl_803E1744;
  }
  else if (pathT < lbl_803E1740) {
    pathT = lbl_803E1740;
  }
  pathT = Curve_EvalHermite(pathT,(float *)(gCamcontrolPathState + 0x10c),(float *)0x0);
  if (pathT < lbl_803E1748) {
    pathT = lbl_803E1748;
  }
  Curve_AdvanceAlongPath(pathT,(float *)(gCamcontrolPathState + 0x120));
  *outX = *(float *)(gCamcontrolPathState + 0x188);
  *outZ = *(float *)(gCamcontrolPathState + 400);
  return;
}
