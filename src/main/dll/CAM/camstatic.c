#include "ghidra_import.h"

extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                           int obj);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                           int obj);
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

extern int *gCameraInterface;
extern u8 *cameraMtxVar57;
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

typedef struct {
    u8 b7 : 1;
    u8 b6 : 1;
    u8 rest : 6;
} CamFlagByte;

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

  psVar4 = *(short **)(param_1 + 0x52);
  if (psVar4 == (short *)0x0) {
    return;
  }
  if (psVar4[0x22] == 1) {
    fn_8029656C((int)psVar4,&local_148);
    lbl_803DD52C = timeDelta * local_148;
    iVar2 = EmissionController_IsLingering((int)psVar4);
    switch (iVar2) {
    case 1:
      *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E16AC;
      *(undefined *)(gCamcontrolModeSettings + 0xc2) = 0xff;
      break;
    case 2:
      *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E1718;
      *(undefined *)(gCamcontrolModeSettings + 0xc2) = 0xc;
      break;
    case 4:
      *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E171C;
      *(undefined *)(gCamcontrolModeSettings + 0xc2) = 2;
      break;
    case 3:
      *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E1720;
      *(undefined *)(gCamcontrolModeSettings + 0xc2) = 8;
      break;
    default:
      *(float *)(gCamcontrolModeSettings + 0x14) = *(float *)(gCamcontrolModeSettings + 0x58);
      *(undefined *)(gCamcontrolModeSettings + 0xc2) = 8;
      break;
    }
  }
  else {
    lbl_803DD52C = timeDelta;
  }
  *(undefined *)(param_1 + 0x9f) = 0;
  camcontrol_updateModeSettings((int)param_1);
  camMoveFn_80104040((int)param_1,(int)psVar4);
  firstperson_updatePosition((int)param_1,psVar4);
  Obj_TransformLocalPointToWorld(*(f32 *)(param_1 + 6),*(f32 *)(param_1 + 8),
                                 *(f32 *)(param_1 + 10),(f32 *)(param_1 + 0xc),
                                 (f32 *)(param_1 + 0xe),(f32 *)(param_1 + 0x10),
                                 *(int *)(param_1 + 0x18));
  camslide_update((int)param_1,(int)psVar4,*(f32 *)(gCamcontrolModeSettings + 0xa0),
                  *(f32 *)(gCamcontrolModeSettings + 0xa4));
  camcontrol_updateVerticalBounds((int)param_1,1,8,(f32 *)(gCamcontrolModeSettings + 0xa0),
                                  (f32 *)(gCamcontrolModeSettings + 0xa4));
  if (((CamFlagByte *)(gCamcontrolModeSettings + 0xc6))->b7 == 0) {
    *(undefined *)(gCamcontrolModeSettings + 0xc5) = *(u8 *)((int)param_1 + 0xa2);
    if (((*(u8 *)((int)param_1 + 0x142) != 0) ||
        ((*(u8 *)(gCamcontrolModeSettings + 0xc5) == 1 &&
         (*(f32 *)(param_1 + 0x1c) >= lbl_803E16AC)))) &&
       (((CamFlagByte *)(gCamcontrolModeSettings + 200))->b7 == 0)) {
      if (((*(f32 *)(param_1 + 0xe) > lbl_803E16DC + *(f32 *)(psVar4 + 0xe)) &&
          (*(f32 *)(param_1 + 0xe) < lbl_803E1724 + *(f32 *)(psVar4 + 0xe))) &&
         (*(int *)(param_1 + 0x18) == 0)) {
        ((CamFlagByte *)(gCamcontrolModeSettings + 0xc6))->b7 = 1;
      }
    }
    if ((((*(u8 *)(gCamcontrolModeSettings + 0xc5) & 0x10) != 0) &&
        (*(f32 *)(param_1 + 0x1c) < lbl_803E1728)) &&
       (*(f32 *)(psVar4 + 0x14) <= lbl_803E16AC)) {
      ((CamFlagByte *)(gCamcontrolModeSettings + 200))->b6 = 1;
      *(f32 *)(gCamcontrolModeSettings + 0xbc) = *(f32 *)(param_1 + 0xe);
    }
  }
  else {
    fVar1 = lbl_803E16AC;
    *(float *)(param_1 + 0x98) = fVar1;
    *(float *)(param_1 + 0x96) = fVar1;
    if ((*(u8 *)((int)param_1 + 0xa2) == 1) && (*(f32 *)(param_1 + 0x1c) < fVar1)) {
      ((CamFlagByte *)(gCamcontrolModeSettings + 0xc6))->b7 = 0;
    }
    if ((*(f32 *)(param_1 + 0xe) > lbl_803E172C + *(f32 *)(psVar4 + 0xe)) ||
       (*(f32 *)(param_1 + 0xe) < lbl_803E1708 + *(f32 *)(psVar4 + 0xe))) {
      ((CamFlagByte *)(gCamcontrolModeSettings + 0xc6))->b7 = 0;
    }
  }
  if (((CamFlagByte *)(gCamcontrolModeSettings + 200))->b7 != 0) {
    if ((*(u8 *)(gCamcontrolModeSettings + 0xc5) == 1) || (*(u8 *)((int)param_1 + 0x142) != 0)) {
      *(u8 *)(gCamcontrolModeSettings + 199) += 1;
    }
    else {
      *(undefined *)(gCamcontrolModeSettings + 199) = 0;
    }
    if (10 < *(u8 *)(gCamcontrolModeSettings + 199)) {
      if (psVar4[0x22] == 1) {
        cameraGetPrevPos2((int)psVar4,&local_128,&local_124,&local_120);
      }
      else {
        local_128 = *(f32 *)(psVar4 + 0xc);
        local_124 = *(f32 *)(psVar4 + 0xe) + *(f32 *)(gCamcontrolModeSettings + 0x8c);
        local_120 = *(f32 *)(psVar4 + 0x10);
      }
      camcontrol_traceMove(lbl_803E1688,&local_128,(f32 *)(param_1 + 0xc),
                           (f32 *)(param_1 + 0xc),auStack_ac,3,1,1);
      *(f32 *)(param_1 + 0x5c) = *(f32 *)(param_1 + 0xc);
      *(f32 *)(param_1 + 0x5e) = *(f32 *)(param_1 + 0xe);
      *(f32 *)(param_1 + 0x60) = *(f32 *)(param_1 + 0x10);
      *(undefined *)(gCamcontrolModeSettings + 199) = 0;
    }
  }
  if (((CamFlagByte *)(gCamcontrolModeSettings + 0xc6))->b7 == 0) {
    if ((*(u8 *)(gCamcontrolModeSettings + 0xc5) & 0x10) != 0) {
      *(u8 *)(gCamcontrolModeSettings + 0xc3) += 1;
    }
    else {
      *(undefined *)(gCamcontrolModeSettings + 0xc3) = 0;
    }
    if (5 < *(u8 *)(gCamcontrolModeSettings + 0xc3)) {
      if (psVar4[0x22] == 1) {
        cameraGetPrevPos2((int)psVar4,&local_134,&local_130,&local_12c);
      }
      else {
        local_134 = *(f32 *)(psVar4 + 0xc);
        local_130 = *(f32 *)(psVar4 + 0xe) + *(f32 *)(gCamcontrolModeSettings + 0x8c);
        local_12c = *(f32 *)(psVar4 + 0x10);
      }
      camcontrol_traceMove(lbl_803E1688,&local_134,(f32 *)(param_1 + 0xc),
                           (f32 *)(param_1 + 0xc),auStack_11c,3,1,1);
      *(f32 *)(param_1 + 0x5c) = *(f32 *)(param_1 + 0xc);
      *(f32 *)(param_1 + 0x5e) = *(f32 *)(param_1 + 0xe);
      *(f32 *)(param_1 + 0x60) = *(f32 *)(param_1 + 0x10);
      *(undefined *)(gCamcontrolModeSettings + 0xc3) = 0;
    }
  }
  (*(void (*)(void *, float *, void *, float *, float *, f32, int))
      (*(int *)(*gCameraInterface + 0x38)))
            (param_1,&local_138,auStack_13c,&local_140,&local_144,
             *(f32 *)(gCamcontrolModeSettings + 0x8c),0);
  sVar4 = getAngle(local_138,local_140);
  *(undefined2 *)(gCamcontrolModeSettings + 0x80) = 0;
  *param_1 = (-0x8000 - sVar4) - *(short *)(gCamcontrolModeSettings + 0x80);
  uVar3 = getAngle(*(f32 *)(param_1 + 0xe) -
                   (*(f32 *)(psVar4 + 0xe) + *(f32 *)(gCamcontrolModeSettings + 0x8c)),
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
                           (f32)(u32)*(u8 *)(gCamcontrolModeSettings + 0xc2),timeDelta);
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
