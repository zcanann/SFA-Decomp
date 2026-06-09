#include "main/dll/CAM/camTalk.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/mm.h"
#include "main/object_transform.h"

extern void *memset(void *dst, int val, u32 n);
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern int FUN_80017730();
extern void vecRotateZXY(void *param_1, void *outVec);
extern undefined4 setMatrixFromObjectPos();
extern void Matrix_TransformPoint(void *matrix, f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ);
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 camcontrol_getTargetPosition(int param_1,int param_2,float *outPos,void *outAngle);
extern int getAngle(f32 dx,f32 dz);
extern void *getSbGalleon(void);
extern int DBprotection_getCameraState(int *obj);
extern double FUN_80293900();
extern f32 mathSinf(f32);
extern f32 sqrtf(f32 value);
extern f32 mathCosf(f32);
extern void cameraGetPrevPos2(int obj, float *x, float *y, float *z);

extern u8* lbl_803DD540;
extern ViewfinderState *lbl_803DD548;
extern f64 lbl_803E17B8;
extern f64 DOUBLE_803e2458;
extern f32 timeDelta;
extern f32 lbl_803E1780;
extern f32 lbl_803E1784;
extern f32 lbl_803E1788;
extern f32 lbl_803E178C;
extern f32 lbl_803E1790;
extern f32 lbl_803E1794;
extern f32 lbl_803E1798;
extern f32 lbl_803E179C;
extern f32 lbl_803E17A0;
extern f32 lbl_803E17A4;
extern f32 lbl_803E17A8;
extern f32 lbl_803E17AC;
extern f32 lbl_803E17B0;
extern f32 lbl_803E17B4;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern f64 lbl_803E17D8;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2448;
extern f32 lbl_803E244C;
extern f32 lbl_803E2450;

/* FUN_80107b4c removed: in v1.0 this address is the start of CameraModeBike_update. */

/*
 * --INFO--
 *
 * Function: CameraModeBike_update
 * EN v1.0 Address: 0x80107B78
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80107DE8
 * EN v1.1 Size: 1076b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void CameraModeBike_update(short *param_1)
{
  int iVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  ushort *puVar5;
  float dVar6;
  float dVar7;
  float dVar8;
  float dVar9;
  float local_108;
  float local_104;
  float local_100;
  CamTalkTransformInput local_fc;
  float afStack_e4 [17];
  longlong local_a0;
  undefined4 local_98;
  uint uStack_94;
  longlong local_90;
  longlong local_88;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  longlong local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;
  
  (*gCameraInterface)->getDefaultHandlerEntry();
  puVar5 = ((CameraObject *)param_1)->anim.targetObj;
  if (puVar5 != (ushort *)0x0) {
    ((CameraObject *)param_1)->fov = lbl_803E1784;
    local_fc.x = *(float *)(puVar5 + 0xc);
    local_fc.y = *(float *)(puVar5 + 0xe);
    local_fc.z = *(float *)(puVar5 + 0x10);
    local_fc.scale = lbl_803E1788;
    local_fc.yaw = *(short *)puVar5;
    local_a0 = (longlong)(int)*(float *)(lbl_803DD540 + 0x30);
    local_fc.pitch = (undefined2)(int)*(float *)(lbl_803DD540 + 0x30);
    local_fc.roll = 0;
    setMatrixFromObjectPos(afStack_e4,&local_fc);
    Matrix_TransformPoint(afStack_e4,lbl_803E1780,lbl_803E178C,lbl_803E1780,
                 &local_100,&local_104,&local_108);
    *param_1 = -0x8000 - *puVar5;
    *(float *)(lbl_803DD540 + 0x20) =
         lbl_803E1790 *
         (lbl_803E1794 * *(float *)(lbl_803DD540 + 0x1c) - *(float *)(lbl_803DD540 + 0x20)) +
         *(float *)(lbl_803DD540 + 0x20);
    iVar1 = (int)((f32)(s32)*param_1 + *(f32 *)(lbl_803DD540 + 0x20));
    *param_1 = (short)iVar1;
    iVar1 = (int)(lbl_803E1798 - *(f32 *)(lbl_803DD540 + 0x30));
    sVar4 = (short)iVar1 - param_1[1];
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    param_1[1] = param_1[1] + (sVar4 >> 3);
    dVar6 = mathSinf(lbl_803E179C * (f32)(s32)((int)*param_1 - 0x4000) / lbl_803E17A0);
    dVar7 = mathCosf(lbl_803E179C * (f32)(s32)((int)*param_1 - 0x4000) / lbl_803E17A0);
    dVar8 = mathCosf(lbl_803E179C * (f32)(s32)param_1[1] / lbl_803E17A0);
    dVar9 = mathSinf(lbl_803E179C * (f32)(s32)param_1[1] / lbl_803E17A0);
    fVar2 = -*(float *)(lbl_803DD540 + 0x24) / lbl_803E17A4;
    fVar3 = (fVar2 < lbl_803E1780) ? lbl_803E1780 : ((fVar2 > lbl_803E1788) ? lbl_803E1788 : fVar2);
    *(float *)(lbl_803DD540 + 0x28) =
         lbl_803E17A8 *
         ((lbl_803E17B0 * fVar3 + lbl_803E17AC) - *(float *)(lbl_803DD540 + 0x28)) +
         *(float *)(lbl_803DD540 + 0x28);
    fVar2 = *(float *)(lbl_803DD540 + 0x28);
    dVar8 = fVar2 * dVar8;
    ((CameraObject *)param_1)->anim.worldPosX = local_100 + dVar8 * dVar7;
    ((CameraObject *)param_1)->anim.worldPosY = local_104 + fVar2 * dVar9;
    ((CameraObject *)param_1)->anim.worldPosZ = local_108 + dVar8 * dVar6;
    iVar1 = (int)(lbl_803E17A8 * *(float *)(lbl_803DD540 + 0x2c));
    local_60 = (longlong)iVar1;
    sVar4 = (short)iVar1 - param_1[2];
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    iVar1 = (int)((f32)(s32)sVar4 * timeDelta * lbl_803E17B4 + (f32)(s32)param_1[2]);
    param_1[2] = (short)iVar1;
    Obj_TransformWorldPointToLocal(((CameraObject *)param_1)->anim.worldPosX,((CameraObject *)param_1)->anim.worldPosY,
                 ((CameraObject *)param_1)->anim.worldPosZ,(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: CameraModeBike_init
 * EN v1.0 Address: 0x80107EE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010821C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeBike_init(int param_1)
{
  if (lbl_803DD540 == 0) {
    lbl_803DD540 = (u8 *)mmAlloc(0x38,0xf,0);
  }
  memset(lbl_803DD540,0,0x38);
  *(float *)(lbl_803DD540 + 0x18) = ((CameraObject *)param_1)->fov;
  *(float *)(lbl_803DD540 + 0) = lbl_803E1784;
  *(float *)(lbl_803DD540 + 0x14) = lbl_803E1788;
  *(float *)(lbl_803DD540 + 0x28) = lbl_803E17AC;
}

/*
 * --INFO--
 *
 * Function: firstPersonPlaceCamera
 * EN v1.0 Address: 0x80107EE4
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801082AC
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void firstPersonPlaceCamera(int param_1,int param_2)
{
  register int self = param_1;
  ViewfinderState *state;
  int *puVar1;
  int iVar2;
  float local_20;
  float local_24;
  float local_28;
  float local_1c[3];

  state = lbl_803DD548;
  if (*(short *)(self + 0x44) == 1) {
    cameraGetPrevPos2(self,&local_28,&local_24,&local_20);
    if (((param_2 != 0) || (state->camPosX != local_28)) ||
       (state->camPosZ != local_20)) {
      state->clampedPosY = local_24;
    }
    state->camPosX = local_28;
    state->camPosY = local_24;
    state->camPosZ = local_20;
  }
  else {
    state->camPosX = *(float *)(self + 0x18);
    state->camPosY = lbl_803E17C0 + *(float *)(self + 0x1c);
    state->camPosZ = *(float *)(self + 0x20);
    state->clampedPosY = state->camPosY;
  }
  puVar1 = (int *)getSbGalleon();
  if (puVar1 != (int *)0x0) {
    iVar2 = DBprotection_getCameraState(puVar1);
    if (iVar2 == 2) {
      local_1c[0] = *(float *)(self + 0x18) - *(float *)(puVar1 + 6);
      local_1c[1] = (lbl_803E17C0 + *(float *)(self + 0x1c)) - *(float *)(puVar1 + 7);
      local_1c[2] = *(float *)(self + 0x20) - *(float *)(puVar1 + 8);
      vecRotateZXY(puVar1,local_1c);
      state->camPosX = *(float *)(puVar1 + 6) + local_1c[0];
      state->camPosY = *(float *)(puVar1 + 7) + local_1c[1];
      state->camPosZ = *(float *)(puVar1 + 8) + local_1c[2];
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: firstPersonExit
 * EN v1.0 Address: 0x80108074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108430
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void firstPersonExit(short *param_1)
{
  register short *self = param_1;
  ViewfinderState *state;
  float fVar1;
  float fVar2;
  int sVar3;
  int iVar4;
  float local_24[3];
  undefined auStack_28[4];

  state = lbl_803DD548;
  iVar4 = *(int *)(self + 0x52);
  state->posXCurve.start = *(float *)(self + 0xc);
  fVar1 = lbl_803E17C4;
  state->posXCurve.startTangent = lbl_803E17C4;
  state->posXCurve.endTangent = fVar1;
  state->posYCurve.start = *(float *)(self + 0xe);
  state->posYCurve.startTangent = fVar1;
  state->posYCurve.endTangent = fVar1;
  state->posZCurve.start = *(float *)(self + 0x10);
  state->posZCurve.startTangent = fVar1;
  state->posZCurve.endTangent = fVar1;
  camcontrol_getTargetPosition((int)self,iVar4,local_24,auStack_28);
  state->posXCurve.end = local_24[0];
  state->posYCurve.end = local_24[1];
  state->posZCurve.end = local_24[2];
  fVar1 = state->posXCurve.end - state->posXCurve.start;
  fVar2 = state->posZCurve.end - state->posZCurve.start;
  state->exitDistance = sqrtf(fVar1 * fVar1 + fVar2 * fVar2);
  state->viewCurve.px = &state->yawCurve.start;
  state->viewCurve.py = &state->pitchCurve.start;
  state->viewCurve.pz = NULL;
  state->viewCurve.count = 4;
  state->viewCurve.dir = 0;
  state->viewCurve.eval = Curve_EvalHermite;
  state->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
  state->yawCurve.start = (float)(int)*self;
  sVar3 = getAngle((double)(state->posXCurve.end - *(float *)(iVar4 + 0x18)),
                   (double)(state->posZCurve.end - *(float *)(iVar4 + 0x20)));
  state->yawCurve.end = (float)(int)(short)(0x8000 - sVar3);
  fVar1 = lbl_803E17C4;
  state->yawCurve.startTangent = lbl_803E17C4;
  state->yawCurve.endTangent = fVar1;
  fVar1 = state->yawCurve.start - state->yawCurve.end;
  if ((lbl_803E17C8 < fVar1) || (fVar1 < lbl_803E17CC)) {
    if (lbl_803E17C4 <= state->yawCurve.start) {
      if (state->yawCurve.end < lbl_803E17C4) {
        state->yawCurve.end = state->yawCurve.end + lbl_803E17D0;
      }
    }
    else {
      state->yawCurve.start = state->yawCurve.start + lbl_803E17D0;
    }
  }
  state->pitchCurve.start = (float)(int)self[1];
  fVar1 = lbl_803E17C4;
  state->pitchCurve.end = lbl_803E17C4;
  state->pitchCurve.startTangent = fVar1;
  state->pitchCurve.endTangent = fVar1;
  fVar1 = state->pitchCurve.start - state->pitchCurve.end;
  if ((lbl_803E17C8 < fVar1) || (fVar1 < lbl_803E17CC)) {
    if (lbl_803E17C4 <= state->pitchCurve.start) {
      if (state->pitchCurve.end < lbl_803E17C4) {
        state->pitchCurve.end = state->pitchCurve.end + lbl_803E17D0;
      }
    }
    else {
      state->pitchCurve.start = state->pitchCurve.start + lbl_803E17D0;
    }
  }
  curvesMove(&state->viewCurve);
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void CameraModeBike_release(void) {}
void CameraModeBike_initialise(void) {}
