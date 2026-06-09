#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"
#include "main/object_transform.h"

extern void camcontrol_traceMove(f32 radius, f32 *from, void *to, f32 *out, void *work, int a,
                                 int b, int c);
extern void camcontrol_updateTargetAction(int camera, int obj);
extern void camMoveFn_80104040(int camera, int obj);
extern void camcontrol_updateModeSettings(int camera);
extern void camcontrol_updateVerticalBounds(int camera, int flags, s8 param_3, f32 *upperBound,
                                            f32 *lowerBound);
extern void camslide_update(int camera, int obj, f32 upper, f32 lower);
extern void firstperson_updatePosition(int camera, void *obj);
extern int EmissionController_IsLingering(int obj);
extern void fn_8029656C(int obj, float *out);
extern void cameraGetPrevPos2(int obj, float *x, float *y, float *z);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 interpolate(f32 cur, f32 target, f32 t);

extern f64 lbl_803E1698;
extern f64 lbl_803E16F8;
extern f32 lbl_803DD52C;
extern f32 lbl_803E1688;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16DC;
extern f32 lbl_803E1708;
extern f32 lbl_803E1718;
extern f32 lbl_803E171C;
extern f32 lbl_803E1720;
extern f32 lbl_803E1724;
extern f32 lbl_803E1728;
extern f32 lbl_803E172C;
extern f32 lbl_803E1730;
extern f32 timeDelta;

#define gCamcontrolModeSettings cameraMtxVar57

/*
 * --INFO--
 *
 * Function: camstatic_update
 * EN v1.0 Address: 0x80105810
 * EN v1.0 Size: 1644b
 * EN v1.1 Address: 0x80105AAC
 * EN v1.1 Size: 1644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camstatic_update(short *param_1)
{
  short *psVar4;
  float fVar1;
  int iVar2;
  uint uVar3;
  short sVar4;
  float local_148;
  float local_144;
  float local_140;
  undefined auStack_13c [4];
  float local_138;
  float local_134;
  float local_130;
  float local_12c;
  float local_128;
  float local_124;
  float local_120;
  undefined auStack_11c [112];
  undefined auStack_ac [116];

  psVar4 = ((CameraObject *)param_1)->anim.targetObj;
  if (psVar4 == (short *)0x0) {
    return;
  }
  if (psVar4[0x22] == 1) {
    fn_8029656C((int)psVar4,&local_148);
    lbl_803DD52C = timeDelta * local_148;
    iVar2 = EmissionController_IsLingering((int)psVar4);
    switch (iVar2) {
    case 1:
      gCamcontrolModeSettings->heightAdjustRate = lbl_803E16AC;
      gCamcontrolModeSettings->yawResponseFrames = 0xff;
      break;
    case 2:
      gCamcontrolModeSettings->heightAdjustRate = lbl_803E1718;
      gCamcontrolModeSettings->yawResponseFrames = 0xc;
      break;
    case 4:
      gCamcontrolModeSettings->heightAdjustRate = lbl_803E171C;
      gCamcontrolModeSettings->yawResponseFrames = 2;
      break;
    case 3:
      gCamcontrolModeSettings->heightAdjustRate = lbl_803E1720;
      gCamcontrolModeSettings->yawResponseFrames = 8;
      break;
    default:
      gCamcontrolModeSettings->heightAdjustRate =
          gCamcontrolModeSettings->targetHeightAdjustRate;
      gCamcontrolModeSettings->yawResponseFrames = 8;
      break;
    }
  }
  else {
    lbl_803DD52C = timeDelta;
  }
  ((CameraObject *)param_1)->unk13E = 0;
  camcontrol_updateModeSettings((int)param_1);
  camMoveFn_80104040((int)param_1,(int)psVar4);
  firstperson_updatePosition((int)param_1,psVar4);
  Obj_TransformLocalPointToWorld(*(f32 *)(param_1 + 6),*(f32 *)(param_1 + 8),
                                 *(f32 *)(param_1 + 10),(f32 *)(param_1 + 0xc),
                                 (f32 *)(param_1 + 0xe),(f32 *)(param_1 + 0x10),
                                 *(int *)(param_1 + 0x18));
  camslide_update((int)param_1,(int)psVar4,gCamcontrolModeSettings->verticalLowerBound,
                  gCamcontrolModeSettings->verticalUpperBound);
  camcontrol_updateVerticalBounds((int)param_1,1,8,&gCamcontrolModeSettings->verticalLowerBound,
                                  &gCamcontrolModeSettings->verticalUpperBound);
  if (gCamcontrolModeSettings->wallAvoidanceFlags.b7 == 0) {
    gCamcontrolModeSettings->targetActionFlags = *(u8 *)((int)param_1 + 0xa2);
    if (((((CameraObject *)param_1)->unk142 != 0) ||
        ((gCamcontrolModeSettings->targetActionFlags == 1 &&
         (*(f32 *)(param_1 + 0x1c) >= lbl_803E16AC)))) &&
       (gCamcontrolModeSettings->clampFlags.b7 == 0)) {
      if (((*(f32 *)(param_1 + 0xe) > lbl_803E16DC + *(f32 *)(psVar4 + 0xe)) &&
          (*(f32 *)(param_1 + 0xe) < lbl_803E1724 + *(f32 *)(psVar4 + 0xe))) &&
         (*(int *)(param_1 + 0x18) == 0)) {
        gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 1;
      }
    }
    if ((((gCamcontrolModeSettings->targetActionFlags & 0x10) != 0) &&
        (*(f32 *)(param_1 + 0x1c) < lbl_803E1728)) &&
       (*(f32 *)(psVar4 + 0x14) <= lbl_803E16AC)) {
      gCamcontrolModeSettings->clampFlags.b6 = 1;
      gCamcontrolModeSettings->heightLockLimit = *(f32 *)(param_1 + 0xe);
    }
  }
  else {
    fVar1 = lbl_803E16AC;
    ((CameraObject *)param_1)->unk130 = fVar1;
    ((CameraObject *)param_1)->unk12C = fVar1;
    if ((*(u8 *)((int)param_1 + 0xa2) == 1) && (*(f32 *)(param_1 + 0x1c) < fVar1)) {
      gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
    }
    if ((*(f32 *)(param_1 + 0xe) > lbl_803E172C + *(f32 *)(psVar4 + 0xe)) ||
       (*(f32 *)(param_1 + 0xe) < lbl_803E1708 + *(f32 *)(psVar4 + 0xe))) {
      gCamcontrolModeSettings->wallAvoidanceFlags.b7 = 0;
    }
  }
  if (gCamcontrolModeSettings->clampFlags.b7 != 0) {
    if ((gCamcontrolModeSettings->targetActionFlags == 1) || (((CameraObject *)param_1)->unk142 != 0)) {
      gCamcontrolModeSettings->wallAvoidanceTimer += 1;
    }
    else {
      gCamcontrolModeSettings->wallAvoidanceTimer = 0;
    }
    if (10 < gCamcontrolModeSettings->wallAvoidanceTimer) {
      if (psVar4[0x22] == 1) {
        cameraGetPrevPos2((int)psVar4,&local_128,&local_124,&local_120);
      }
      else {
        local_128 = *(f32 *)(psVar4 + 0xc);
        local_124 = *(f32 *)(psVar4 + 0xe) + gCamcontrolModeSettings->targetHeight;
        local_120 = *(f32 *)(psVar4 + 0x10);
      }
      camcontrol_traceMove(lbl_803E1688,&local_128,(f32 *)(param_1 + 0xc),
                           (f32 *)(param_1 + 0xc),auStack_ac,3,1,1);
      ((CameraObject *)param_1)->probePosX = *(f32 *)(param_1 + 0xc);
      ((CameraObject *)param_1)->probePosY = *(f32 *)(param_1 + 0xe);
      ((CameraObject *)param_1)->probePosZ = *(f32 *)(param_1 + 0x10);
      gCamcontrolModeSettings->wallAvoidanceTimer = 0;
    }
  }
  if (gCamcontrolModeSettings->wallAvoidanceFlags.b7 == 0) {
    if ((gCamcontrolModeSettings->targetActionFlags & 0x10) != 0) {
      gCamcontrolModeSettings->collisionProbeTimer += 1;
    }
    else {
      gCamcontrolModeSettings->collisionProbeTimer = 0;
    }
    if (5 < gCamcontrolModeSettings->collisionProbeTimer) {
      if (psVar4[0x22] == 1) {
        cameraGetPrevPos2((int)psVar4,&local_134,&local_130,&local_12c);
      }
      else {
        local_134 = *(f32 *)(psVar4 + 0xc);
        local_130 = *(f32 *)(psVar4 + 0xe) + gCamcontrolModeSettings->targetHeight;
        local_12c = *(f32 *)(psVar4 + 0x10);
      }
      camcontrol_traceMove(lbl_803E1688,&local_134,(f32 *)(param_1 + 0xc),
                           (f32 *)(param_1 + 0xc),auStack_11c,3,1,1);
      ((CameraObject *)param_1)->probePosX = *(f32 *)(param_1 + 0xc);
      ((CameraObject *)param_1)->probePosY = *(f32 *)(param_1 + 0xe);
      ((CameraObject *)param_1)->probePosZ = *(f32 *)(param_1 + 0x10);
      gCamcontrolModeSettings->collisionProbeTimer = 0;
    }
  }
  (*gCameraInterface)->getRelativePosition(gCamcontrolModeSettings->targetHeight,
                                           (int)param_1, &local_138, (f32 *)auStack_13c,
                                           &local_140, &local_144, 0);
  sVar4 = getAngle(local_138,local_140);
  gCamcontrolModeSettings->pitchOffset = 0;
  *param_1 = (-0x8000 - sVar4) - gCamcontrolModeSettings->pitchOffset;
  uVar3 = getAngle(*(f32 *)(param_1 + 0xe) -
                   (*(f32 *)(psVar4 + 0xe) + gCamcontrolModeSettings->targetHeight),
                   local_144);
  uVar3 = (uVar3 & 0xffff) - ((int)param_1[1] & 0xffffU);
  if (0x8000 < (int)uVar3) {
    uVar3 = uVar3 - 0xffff;
  }
  if ((int)uVar3 < -0x8000) {
    uVar3 = uVar3 + 0xffff;
  }
  iVar2 = (int)interpolate((f32)(int)uVar3,
                           lbl_803E16A4 /
                           (f32)(u32)gCamcontrolModeSettings->yawResponseFrames,timeDelta);
  param_1[1] = param_1[1] + (short)iVar2;
  camcontrol_updateTargetAction((int)param_1,(int)psVar4);
  iVar2 = (int)interpolate((f32)param_1[2],lbl_803E1730,timeDelta);
  param_1[2] = param_1[2] - (short)iVar2;
  Obj_TransformWorldPointToLocal(*(f32 *)(param_1 + 0xc),*(f32 *)(param_1 + 0xe),
                                 *(f32 *)(param_1 + 0x10),(f32 *)(param_1 + 6),
                                 (f32 *)(param_1 + 8),(f32 *)(param_1 + 10),
                                 *(int *)(param_1 + 0x18));
}
#pragma peephole reset
#pragma scheduling reset
