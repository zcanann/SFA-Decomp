#include "ghidra_import.h"
#include "main/dll/dll_EC.h"

extern void *Obj_GetPlayerObject(void);
extern int randomGetRange(int min,int max);
extern void fn_802960E4(double xVelocity,double zVelocity,int obj);

extern f32 lbl_803E6438;
extern f64 lbl_803E6440;
extern f32 lbl_803E644C;

typedef struct TrickyCurveDoubleBits {
  undefined4 hi;
  uint lo;
} TrickyCurveDoubleBits;

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateCooldownTrigger
 * EN v1.0 Address: 0x80206F30
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x80206FA0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TrickyCurve_updateCooldownTrigger(int obj)
{
  float deltaX;
  float deltaY;
  float deltaZ;
  int playerObj;
  int axisCount;
  uint randomValue;
  short *state;
  TrickyCurveDoubleBits bits;
  double randomX;
  double randomZ;
  
  state = *(short **)(obj + 0xb8);
  playerObj = (int)Obj_GetPlayerObject();
  axisCount = 0;
  deltaX = *(float *)(playerObj + 0xc) - *(float *)(obj + 0xc);
  deltaY = *(float *)(playerObj + 0x10) - *(float *)(obj + 0x10);
  deltaZ = *(float *)(playerObj + 0x14) - *(float *)(obj + 0x14);
  if (deltaX <= lbl_803E6438) {
    bits.hi = 0x43300000;
    bits.lo = (int)*state ^ 0x80000000;
    if (-(float)(*(double *)&bits - lbl_803E6440) < deltaX) {
      axisCount = 1;
    }
  }
  if (lbl_803E6438 < deltaX) {
    bits.hi = 0x43300000;
    bits.lo = (int)*state ^ 0x80000000;
    if (deltaX < (float)(*(double *)&bits - lbl_803E6440)) {
      axisCount = axisCount + 1;
    }
  }
  if (deltaZ <= lbl_803E6438) {
    bits.hi = 0x43300000;
    bits.lo = (int)state[1] ^ 0x80000000;
    if (-(float)(*(double *)&bits - lbl_803E6440) < deltaZ) {
      axisCount = axisCount + 1;
    }
  }
  if (lbl_803E6438 < deltaZ) {
    bits.hi = 0x43300000;
    bits.lo = (int)state[1] ^ 0x80000000;
    if (deltaZ < (float)(*(double *)&bits - lbl_803E6440)) {
      axisCount = axisCount + 1;
    }
  }
  if (deltaY <= lbl_803E6438) {
    bits.hi = 0x43300000;
    bits.lo = (int)state[2] ^ 0x80000000;
    if (-(float)(*(double *)&bits - lbl_803E6440) < deltaY) {
      axisCount = axisCount + 1;
    }
  }
  if (lbl_803E6438 < deltaY) {
    bits.hi = 0x43300000;
    bits.lo = (int)state[2] ^ 0x80000000;
    if (deltaY < (float)(*(double *)&bits - lbl_803E6440)) {
      axisCount = axisCount + 1;
    }
  }
  if (axisCount == 3) {
    randomValue = randomGetRange(-0x17,0x17);
    bits.hi = 0x43300000;
    bits.lo = randomValue ^ 0x80000000;
    randomX = (double)(float)(*(double *)&bits - lbl_803E6440);
    randomValue = randomGetRange(-0x17,0x17);
    bits.hi = 0x43300000;
    bits.lo = randomValue ^ 0x80000000;
    randomZ = (double)(float)(*(double *)&bits - lbl_803E6440);
    fn_802960E4((double)(lbl_803E644C * (float)randomX),
                (double)(lbl_803E644C * (float)randomZ),playerObj);
  }
  return;
}
