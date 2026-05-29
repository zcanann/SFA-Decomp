#include "ghidra_import.h"
#include "main/dll/CAM/camcontrol.h"
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
extern void camcontrol_activateHandler(u32 actionId,void *actionData);

extern s16 lbl_803DD4C0;
extern char sDllBBTimeDebugFormat[];
extern f64 lbl_803E1650;
extern f32 timeDelta;
extern f32 lbl_803DD4D0;
extern f32 lbl_803E162C;
extern f32 lbl_803E1630;
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
#pragma scheduling off
#pragma peephole off
void camcontrol_applyState(short *param_1)
{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  float fVar5;
  float fVar6;
  float delta[3];
  undefined8 local_28;
  undefined8 local_20;
  
  Camera_SetCurrentViewIndex(0);
  psVar3 = (short *)Camera_GetCurrentViewSlot();
  *psVar3 = *param_1;
  psVar3[1] = param_1[1];
  psVar3[2] = param_1[2];
  if ((*(byte *)((int)param_1 + 0x143) & 0x80) != 0) {
    PSVECSubtract((float *)(param_1 + 0xc),(float *)(psVar3 + 6),delta);
    fVar5 = PSVECMag(delta);
    if (lbl_803E1630 < fVar5) {
      PSVECNormalize(delta,delta);
    }
    fVar6 = interpolate(fVar5,lbl_803E1668,timeDelta);
    fVar5 = lbl_803E1630;
    if ((fVar5 <= fVar6) && (fVar5 = fVar6, (lbl_803E166C * timeDelta) < fVar6)) {
      fVar5 = lbl_803E166C * timeDelta;
    }
    *(float *)(psVar3 + 6) = fVar5 * delta[0] + *(float *)(psVar3 + 6);
    *(float *)(psVar3 + 8) = fVar5 * delta[1] + *(float *)(psVar3 + 8);
    *(float *)(psVar3 + 10) = fVar5 * delta[2] + *(float *)(psVar3 + 10);
  }
  else {
    *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(param_1 + 0x10);
  }
  fVar2 = lbl_803E1630;
  lbl_803DD4D0 = *(float *)(param_1 + 0x5a);
  if (lbl_803E1630 < *(float *)(param_1 + 0x7a)) {
    *(float *)(param_1 + 0x7a) =
         -(*(float *)(param_1 + 0x7c) * timeDelta - *(float *)(param_1 + 0x7a));
    fVar1 = *(float *)(param_1 + 0x7a);
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, lbl_803E162C < fVar1)) {
      fVar2 = lbl_803E162C;
    }
    *(float *)(param_1 + 0x7a) = fVar2;
    if (pCamera[0x139] == '\x02') {
      fVar2 = *(float *)(param_1 + 0x7a);
      fVar5 = lbl_803E162C - fVar2 * fVar2 * fVar2;
    }
    else if (pCamera[0x139] == '\x01') {
      fVar5 = lbl_803E162C - *(float *)(param_1 + 0x7a) * *(float *)(param_1 + 0x7a);
    }
    else {
      fVar5 = lbl_803E162C - *(float *)(param_1 + 0x7a);
    }
    fVar6 = lbl_803E1630;
    if ((fVar6 <= fVar5) && (fVar6 = fVar5, lbl_803E162C < fVar5)) {
      fVar6 = lbl_803E162C;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 8) != 0) {
      *(float *)(psVar3 + 6) =
           fVar6 * (*(float *)(psVar3 + 6) - *(float *)(param_1 + 0x86)) +
           *(float *)(param_1 + 0x86);
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 0x10) != 0) {
      *(float *)(psVar3 + 8) =
           fVar6 * (*(float *)(psVar3 + 8) - *(float *)(param_1 + 0x88)) +
           *(float *)(param_1 + 0x88);
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 0x20) != 0) {
      *(float *)(psVar3 + 10) =
           fVar6 * (*(float *)(psVar3 + 10) - *(float *)(param_1 + 0x8a)) +
           *(float *)(param_1 + 0x8a);
    }
    OSReport(sDllBBTimeDebugFormat,fVar6);
    if ((*(byte *)((int)param_1 + 0x13f) & 1) != 0) {
      param_1[0x80] = param_1[0x83] - *psVar3;
      if (0x8000 < param_1[0x80]) {
        param_1[0x80] = param_1[0x80] + 1;
      }
      if (param_1[0x80] < -0x8000) {
        param_1[0x80] = param_1[0x80] + -1;
      }
      local_28 = (double)CONCAT44(0x43300000,(int)param_1[0x80] ^ 0x80000000);
      iVar4 = (int)((float)(local_28 - lbl_803E1650) * fVar6);
      local_20 = (double)(longlong)iVar4;
      *psVar3 = param_1[0x83] - (short)iVar4;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 2) != 0) {
      param_1[0x81] = param_1[0x84] - psVar3[1];
      if (0x8000 < param_1[0x81]) {
        param_1[0x81] = param_1[0x81] + 1;
      }
      if (param_1[0x81] < -0x8000) {
        param_1[0x81] = param_1[0x81] + -1;
      }
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[0x81] ^ 0x80000000);
      iVar4 = (int)((float)(local_20 - lbl_803E1650) * fVar6);
      local_28 = (double)(longlong)iVar4;
      psVar3[1] = param_1[0x84] - (short)iVar4;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 4) != 0) {
      param_1[0x82] = param_1[0x85] - psVar3[2];
      if (0x8000 < param_1[0x82]) {
        param_1[0x82] = param_1[0x82] + 1;
      }
      if (param_1[0x82] < -0x8000) {
        param_1[0x82] = param_1[0x82] + -1;
      }
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[0x82] ^ 0x80000000);
      iVar4 = (int)((float)(local_20 - lbl_803E1650) * fVar6);
      local_28 = (double)(longlong)iVar4;
      psVar3[2] = param_1[0x85] - (short)iVar4;
    }
  }
  Camera_SetFovY(lbl_803DD4D0);
  Obj_UpdateWorldTransform(psVar3);
  loadMapForCameraPos(*(float *)(param_1 + 0xc),*(float *)(param_1 + 0xe),
                      *(float *)(param_1 + 0x10));
  iVar4 = Camera_GetViewportYOffset();
  lbl_803DD4C0 = (short)iVar4;
  if ((int)lbl_803DD4C0 != (int)*(char *)((int)param_1 + 0x13b)) {
    if ((int)lbl_803DD4C0 < (int)*(char *)((int)param_1 + 0x13b)) {
      local_20 = (double)(longlong)(int)timeDelta;
      lbl_803DD4C0 = lbl_803DD4C0 + (short)*(char *)(param_1 + 0x9e) * (short)(int)timeDelta;
      if ((int)*(char *)((int)param_1 + 0x13b) < (int)lbl_803DD4C0) {
        lbl_803DD4C0 = (short)*(char *)((int)param_1 + 0x13b);
      }
    }
    else {
      local_20 = (double)(longlong)(int)timeDelta;
      lbl_803DD4C0 = lbl_803DD4C0 - (short)*(char *)(param_1 + 0x9e) * (short)(int)timeDelta;
      if ((int)lbl_803DD4C0 < (int)*(char *)((int)param_1 + 0x13b)) {
        lbl_803DD4C0 = (short)*(char *)((int)param_1 + 0x13b);
      }
    }
    Camera_SetViewportYOffset(lbl_803DD4C0);
  }
  *(undefined *)((int)param_1 + 0x13b) = 0;
  Camera_UpdateViewMatrices();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: camcontrol_applyQueuedAction
 * EN v1.0 Address: 0x80101EBC
 * EN v1.0 Size: 400b
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_applyQueuedAction(void)
{
  CameraViewSlot *view;
  float blendStep;

  if (gCamcontrolQueuedActionPending != '\0') {
    if (gCamcontrolQueuedActionBlendFrames > 1) {
      blendStep = lbl_803E162C / (float)gCamcontrolQueuedActionBlendFrames;
      if ((blendStep <= lbl_803E1630) || (blendStep > lbl_803E162C)) {
        blendStep = lbl_803E162C;
      }
      *(float *)(pCamera + 0xf4) = lbl_803E162C;
      *(float *)(pCamera + 0xf8) = blendStep;
      pCamera[0x13f] = gCamcontrolQueuedActionMode;
    }
    else {
      *(float *)(pCamera + 0xf4) = lbl_803E1630;
      pCamera[0x13f] = 0;
    }
    view = Camera_GetCurrentViewSlot();
    if (lbl_803E162C == *(float *)(pCamera + 0xf4)) {
      *(float *)(pCamera + 0x10c) = view->x;
      *(float *)(pCamera + 0x110) = view->y;
      *(float *)(pCamera + 0x114) = view->z;
      *(short *)(pCamera + 0x106) = view->yaw;
      *(short *)(pCamera + 0x108) = view->pitch;
      *(short *)(pCamera + 0x10a) = view->roll;
      *(float *)(pCamera + 0x118) = Camera_GetFovY();
    }
    else {
      *(short *)pCamera = view->yaw;
      *(short *)(pCamera + 2) = view->pitch;
      *(short *)(pCamera + 4) = view->roll;
      *(float *)(pCamera + 0xb4) = Camera_GetFovY();
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

void Camera_func1D(int param_1)
{
  pCamera[0x141] = (u8)(pCamera[0x141] | ((param_1 << 3) & 0x18));
}

void Camera_func13(int enable)
{
  if (enable != 0) {
    pCamera[0x141] = (u8)(pCamera[0x141] | 2);
  }
  else {
    pCamera[0x141] = (u8)(pCamera[0x141] & ~2);
  }
}

void Camera_func1C(int flags)
{
  pCamera[0x140] = (u8)(pCamera[0x140] | flags);
}

void Camera_setLetterbox(int yOffset,int applyNow)
{
  if (yOffset > (int)(s8)pCamera[0x13b]) {
    ((s8 *)pCamera)[0x13b] = yOffset;
    pCamera[0x13c] = 2;
    if (applyNow != 0) {
      Camera_SetViewportYOffset((s16)yOffset);
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
