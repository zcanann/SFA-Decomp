#include "ghidra_import.h"
#include "main/dll/CAM/attention.h"

extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,
                                           int obj);
extern int objBboxFn_800640cc(int startPoints,int endPoints,int radii,int hitOut,int objOut,
                              int pointCount,int mask,int flags,int mode);
extern int hitDetectFn_80065e50(f32 x,f32 y,f32 z,int obj,int *hitsOut,int pointCount,
                                int mask);
extern void hitDetectFn_80067958(int obj,float *startPoints,float *endPoints,int pointCount,
                                 int outPos,int mode);
extern void hitDetectFn_800691c0(int obj,uint *bounds,int mask,int flags);
extern void fn_8006961C(uint *boundsOut,float *startPoints,float *endPoints,float *radii,
                        int pointCount);
extern f32 *cameraMtxVar57;
extern f32 lbl_803E1688;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16B4;
extern f32 lbl_803E16D0;
extern f32 lbl_803E16D4;

/*
 * --INFO--
 *
 * Function: camcontrol_updateVerticalBounds
 * EN v1.0 Address: 0x801046F4
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x80104990
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_updateVerticalBounds(int camera,int flags,s8 param_3,float *upperBound,
                                     float *lowerBound)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  int iVar9;
  int iVar8;
  int iVar10;
  int iVar11;
  int iVar12;
  int local_40;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  uint auStack_30 [12];
  
  iVar7 = camera;
  iVar11 = *(int *)(iVar7 + 0xa4);
  if ((flags & 1) != 0) {
    *(float *)(iVar7 + 0x74) = lbl_803E1688;
    *(undefined *)(iVar7 + 0x84) = 0xff;
    *(undefined *)(iVar7 + 0x88) = param_3;
    iVar9 = objBboxFn_800640cc(iVar7 + 0xb8,iVar7 + 0x18,1,0,0,0x10,0xffffffff,0xff,0);
    *(u8 *)(iVar7 + 0x142) = iVar9;
    local_3c = *(float *)(iVar7 + 0x18);
    local_38 = *(undefined4 *)(iVar7 + 0x1c);
    local_34 = *(undefined4 *)(iVar7 + 0x20);
    fn_8006961C(auStack_30,(float *)(iVar7 + 0xb8),&local_3c,(float *)(iVar7 + 0x74),1);
    hitDetectFn_800691c0(iVar11,auStack_30,0x240,1);
    hitDetectFn_80067958(iVar11,(float *)(iVar7 + 0xb8),&local_3c,1,iVar7 + 0x34,0);
    *(float *)(iVar7 + 0x18) = local_3c;
    *(undefined4 *)(iVar7 + 0x1c) = local_38;
    *(undefined4 *)(iVar7 + 0x20) = local_34;
  }
  if ((flags & 2) != 0) {
    iVar8 = hitDetectFn_80065e50(*(float *)(iVar7 + 0x18),*(float *)(iVar7 + 0x1c),
                                 *(float *)(iVar7 + 0x20),iVar11,&local_40,1,0x40);
    *upperBound = lbl_803E16D0;
    fVar5 = lbl_803E16D4;
    *lowerBound = lbl_803E16D4;
    fVar2 = lbl_803E16B4;
    fVar6 = lbl_803E16AC;
    iVar10 = 0;
    iVar12 = iVar8;
    fVar3 = fVar5;
    if (0 < iVar8) {
      do {
        if ((*(float **)(local_40 + iVar10))[2] < fVar6) {
          fVar1 = **(float **)(local_40 + iVar10);
          if (*(float *)(iVar7 + 0x1c) - fVar2 < fVar1) {
            fVar4 = *(float *)(iVar7 + 0x1c) - fVar1;
            if (fVar4 < fVar6) {
              fVar4 = -fVar4;
            }
            if (fVar4 < fVar3) {
              *lowerBound = fVar1;
              *(undefined4 *)(iVar7 + 300) = *(undefined4 *)(*(int *)(local_40 + iVar10) + 8);
              fVar3 = fVar4;
            }
          }
        }
        iVar10 = iVar10 + 4;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
    }
    fVar6 = lbl_803E16B4;
    fVar3 = lbl_803E16AC;
    iVar12 = 0;
    if (0 < iVar8) {
      do {
        if (fVar3 < (*(float **)(local_40 + iVar12))[2]) {
          fVar2 = **(float **)(local_40 + iVar12);
          if (fVar2 < fVar6 + *(float *)(iVar7 + 0x1c)) {
            fVar1 = *(float *)(iVar7 + 0x1c) - fVar2;
            if (fVar1 < fVar3) {
              fVar1 = -fVar1;
            }
            if (fVar1 < fVar5) {
              *upperBound = fVar2;
              *(undefined4 *)(iVar7 + 0x130) = *(undefined4 *)(*(int *)(local_40 + iVar12) + 8);
              fVar5 = fVar1;
            }
          }
        }
        iVar12 = iVar12 + 4;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
  }
  Obj_TransformWorldPointToLocal(*(float *)(iVar7 + 0x18),*(float *)(iVar7 + 0x1c),
                                 *(float *)(iVar7 + 0x20),(float *)(iVar7 + 0xc),
                                 (float *)(iVar7 + 0x10),(float *)(iVar7 + 0x14),
                                 *(int *)(iVar7 + 0x30));
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: CameraModeNormal_func0A
 * EN v1.0 Address: 0x80104958
 * EN v1.0 Size: 88b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void CameraModeNormal_func0A(float *distanceOut,float *yOffsetOut,float *zOffsetOut,
                             float *xAngleOut,float *targetHeightOut)
{
  *distanceOut = cameraMtxVar57[0];
  *yOffsetOut = cameraMtxVar57[1];
  if (zOffsetOut != (float *)0x0) {
    *zOffsetOut = cameraMtxVar57[2];
  }
  if (xAngleOut != (float *)0x0) {
    *xAngleOut = cameraMtxVar57[3];
  }
  if (targetHeightOut != (float *)0x0) {
    *targetHeightOut = cameraMtxVar57[0x23];
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
