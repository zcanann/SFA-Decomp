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
extern void hitDetect_calcSweptSphereBounds(uint *boundsOut,float *startPoints,float *endPoints,float *radii,
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
void camcontrol_updateVerticalBounds(int camera,int flags,int param_3,float *upperBound,
                                     float *lowerBound)
{
  float zLim;
  float pt0;
  float zB;
  float diff;
  float bestUpper;
  float bestLower;
  int res;
  int count;
  int i;
  int j;
  int off;
  int off2;
  int camObj;
  uint bounds[6];
  f32 pos[3];
  int hits;

  camObj = *(int *)(camera + 0xa4);
  if ((flags & 1) != 0) {
    zB = lbl_803E1688;
    *(float *)(camera + 0x74) = zB;
    *(s8 *)(camera + 0x84) = -1;
    *(s8 *)(camera + 0x88) = (s8)param_3;
    res = objBboxFn_800640cc(camera + 0xb8,camera + 0x18,1,0,0,0x10,0xffffffff,0xff,0);
    *(u8 *)(camera + 0x142) = res;
    pos[0] = *(f32 *)(camera + 0x18);
    pos[1] = *(f32 *)(camera + 0x1c);
    pos[2] = *(f32 *)(camera + 0x20);
    hitDetect_calcSweptSphereBounds(bounds,(float *)(camera + 0xb8),pos,(float *)(camera + 0x74),1);
    hitDetectFn_800691c0(camObj,bounds,0x240,1);
    hitDetectFn_80067958(camObj,(float *)(camera + 0xb8),pos,1,camera + 0x34,0);
    *(f32 *)(camera + 0x18) = pos[0];
    *(f32 *)(camera + 0x1c) = pos[1];
    *(f32 *)(camera + 0x20) = pos[2];
  }
  if ((flags & 2) != 0) {
    count = hitDetectFn_80065e50(*(float *)(camera + 0x18),*(float *)(camera + 0x1c),
                                 *(float *)(camera + 0x20),camObj,&hits,1,0x40);
    *upperBound = lbl_803E16D0;
    bestUpper = (*lowerBound = lbl_803E16D4);
    bestLower = bestUpper;
    off = 0;
    zLim = lbl_803E16AC;
    for (i = 0; i < count; i++) {
      zB = lbl_803E16B4;
      if ((*(float **)(hits + off))[2] < zLim) {
        pt0 = **(float **)(hits + off);
        if (pt0 > *(float *)(camera + 0x1c) - zB) {
          diff = *(float *)(camera + 0x1c) - pt0;
          if (diff < zLim) {
            diff = -diff;
          }
          if (diff < bestLower) {
            *lowerBound = pt0;
            *(f32 *)(camera + 0x12c) = (*(float **)(hits + off))[2];
            bestLower = diff;
          }
        }
      }
      off += 4;
    }
    off2 = 0;
    zLim = lbl_803E16AC;
    for (j = 0; j < count; j++) {
      zB = lbl_803E16B4;
      if ((*(float **)(hits + off2))[2] > zLim) {
        pt0 = **(float **)(hits + off2);
        if (pt0 < zB + *(float *)(camera + 0x1c)) {
          diff = *(float *)(camera + 0x1c) - pt0;
          if (diff < zLim) {
            diff = -diff;
          }
          if (diff < bestUpper) {
            *upperBound = pt0;
            *(f32 *)(camera + 0x130) = (*(float **)(hits + off2))[2];
            bestUpper = diff;
          }
        }
      }
      off2 += 4;
    }
  }
  Obj_TransformWorldPointToLocal(*(float *)(camera + 0x18),*(float *)(camera + 0x1c),
                                 *(float *)(camera + 0x20),(float *)(camera + 0xc),
                                 (float *)(camera + 0x10),(float *)(camera + 0x14),
                                 *(int *)(camera + 0x30));
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
