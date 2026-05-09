#include "ghidra_import.h"
#include "main/dll/CAM/camcannon.h"

extern double fn_80010C50();
extern double curveFn_80010dc0();
extern undefined4 FUN_80017814();
extern f32 sqrtf(f32 x);

extern int *lbl_803DCA50;
extern undefined4 lbl_803DD560;
extern f64 lbl_803E18A0;
extern f32 timeDelta;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 lbl_803E1890;
extern f32 lbl_803E1894;
extern f32 lbl_803E1898;
extern f32 lbl_803E18AC;
extern f32 lbl_803E18B0;
extern f32 lbl_803E18B4;
extern f32 lbl_803E18B8;

/*
 * --INFO--
 *
 * Function: fn_8010AEA8
 * EN v1.0 Address: 0x8010AEA8
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x8010B144
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint fn_8010AEA8(short *param_1,uint param_2)
{
  float fVar1;
  double dVar2;
  double dVar3;
  undefined8 local_28;
  
  *(undefined4 *)(lbl_803DD560 + 0x14) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(lbl_803DD560 + 0x1c) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(lbl_803DD560 + 0x24) = *(undefined4 *)(param_1 + 10);
  dVar2 = lbl_803E18A0;
  *(float *)(lbl_803DD560 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - lbl_803E18A0);
  *(float *)(lbl_803DD560 + 0x34) =
       (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar2);
  local_28 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
  *(float *)(lbl_803DD560 + 0x3c) = (float)(local_28 - dVar2);
  *(undefined4 *)(lbl_803DD560 + 0x44) = *(undefined4 *)(param_1 + 0x5a);
  dVar2 = (double)lbl_803E1888;
  if (dVar2 != (double)*(float *)(lbl_803DD560 + 0x60)) {
    dVar2 = (double)(float)((double)*(float *)(lbl_803DD560 + 0x5c) /
                           (double)*(float *)(lbl_803DD560 + 0x60));
  }
  if ((double)lbl_803E188C < dVar2) {
    dVar2 = (double)lbl_803E188C;
  }
  dVar2 = curveFn_80010dc0(dVar2,(float *)(lbl_803DD560 + 0x48),(float *)0x0);
  if (dVar2 < (double)lbl_803E18AC) {
    dVar2 = (double)lbl_803E18AC;
  }
  *(float *)(lbl_803DD560 + 0x5c) =
       (float)(dVar2 * (double)timeDelta + (double)*(float *)(lbl_803DD560 + 0x5c));
  dVar2 = (double)lbl_803E1888;
  if (dVar2 != (double)*(float *)(lbl_803DD560 + 0x60)) {
    dVar2 = (double)(float)((double)*(float *)(lbl_803DD560 + 0x5c) /
                           (double)*(float *)(lbl_803DD560 + 0x60));
  }
  if ((double)lbl_803E188C < dVar2) {
    dVar2 = (double)lbl_803E188C;
  }
  dVar3 = fn_80010C50(dVar2,(float *)(lbl_803DD560 + 0x10));
  *(float *)(param_1 + 6) = (float)dVar3;
  dVar3 = fn_80010C50(dVar2,(float *)(lbl_803DD560 + 0x18));
  *(float *)(param_1 + 8) = (float)dVar3;
  dVar3 = fn_80010C50(dVar2,(float *)(lbl_803DD560 + 0x20));
  *(float *)(param_1 + 10) = (float)dVar3;
  dVar3 = fn_80010C50(dVar2,(float *)(lbl_803DD560 + 0x40));
  *(float *)(param_1 + 0x5a) = (float)dVar3;
  fVar1 = *(float *)(lbl_803DD560 + 0x28) - *(float *)(lbl_803DD560 + 0x2c);
  if ((lbl_803E1890 < fVar1) || (fVar1 < lbl_803E1894)) {
    if (lbl_803E1888 <= *(float *)(lbl_803DD560 + 0x28)) {
      if (*(float *)(lbl_803DD560 + 0x2c) < lbl_803E1888) {
        *(float *)(lbl_803DD560 + 0x2c) = *(float *)(lbl_803DD560 + 0x2c) + lbl_803E1898;
      }
    }
    else {
      *(float *)(lbl_803DD560 + 0x28) = *(float *)(lbl_803DD560 + 0x28) + lbl_803E1898;
    }
  }
  fVar1 = *(float *)(lbl_803DD560 + 0x30) - *(float *)(lbl_803DD560 + 0x34);
  if ((lbl_803E1890 < fVar1) || (fVar1 < lbl_803E1894)) {
    if (lbl_803E1888 <= *(float *)(lbl_803DD560 + 0x30)) {
      if (*(float *)(lbl_803DD560 + 0x34) < lbl_803E1888) {
        *(float *)(lbl_803DD560 + 0x34) = *(float *)(lbl_803DD560 + 0x34) + lbl_803E1898;
      }
    }
    else {
      *(float *)(lbl_803DD560 + 0x30) = *(float *)(lbl_803DD560 + 0x30) + lbl_803E1898;
    }
  }
  fVar1 = *(float *)(lbl_803DD560 + 0x38) - *(float *)(lbl_803DD560 + 0x3c);
  if ((lbl_803E1890 < fVar1) || (fVar1 < lbl_803E1894)) {
    if (lbl_803E1888 <= *(float *)(lbl_803DD560 + 0x38)) {
      if (*(float *)(lbl_803DD560 + 0x3c) < lbl_803E1888) {
        *(float *)(lbl_803DD560 + 0x3c) = *(float *)(lbl_803DD560 + 0x3c) + lbl_803E1898;
      }
    }
    else {
      *(float *)(lbl_803DD560 + 0x38) = *(float *)(lbl_803DD560 + 0x38) + lbl_803E1898;
    }
  }
  if ((param_2 & 1) == 0) {
    dVar3 = fn_80010C50(dVar2,(float *)(lbl_803DD560 + 0x28));
    *param_1 = (short)(int)dVar3;
  }
  if ((param_2 & 2) == 0) {
    dVar3 = fn_80010C50(dVar2,(float *)(lbl_803DD560 + 0x30));
    param_1[1] = (short)(int)dVar3;
  }
  if ((param_2 & 4) == 0) {
    dVar3 = fn_80010C50(dVar2,(float *)(lbl_803DD560 + 0x38));
    param_1[2] = (short)(int)dVar3;
  }
  return ((uint)(byte)(((double)lbl_803E188C <= dVar2) << 1) << 0x1c) >> 0x1d;
}

/*
 * --INFO--
 *
 * Function: cameraModeTestStrengthFn_8010b238
 * EN v1.0 Address: 0x8010B218
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x8010B4D4
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cameraModeTestStrengthFn_8010b238(f32 param_1,short *param_2,undefined4 *param_3,uint param_4,uint param_5,
                 uint param_6)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  
  *(undefined *)(lbl_803DD560 + 100) = 0;
  *(undefined4 *)(lbl_803DD560 + 0x10) = *(undefined4 *)(param_2 + 6);
  *(undefined4 *)(lbl_803DD560 + 0x18) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(lbl_803DD560 + 0x20) = *(undefined4 *)(param_2 + 10);
  dVar4 = lbl_803E18A0;
  *(float *)(lbl_803DD560 + 0x28) =
       (float)((double)CONCAT44(0x43300000,(int)*param_2 ^ 0x80000000) - lbl_803E18A0);
  *(float *)(lbl_803DD560 + 0x30) =
       (float)((double)CONCAT44(0x43300000,(int)param_2[1] ^ 0x80000000) - dVar4);
  *(float *)(lbl_803DD560 + 0x38) =
       (float)((double)CONCAT44(0x43300000,(int)param_2[2] ^ 0x80000000) - dVar4);
  *(undefined4 *)(lbl_803DD560 + 0x40) = *(undefined4 *)(param_2 + 0x5a);
  *(undefined4 *)(lbl_803DD560 + 0x14) = *param_3;
  *(undefined4 *)(lbl_803DD560 + 0x1c) = param_3[1];
  *(undefined4 *)(lbl_803DD560 + 0x24) = param_3[2];
  *(float *)(lbl_803DD560 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - dVar4);
  *(float *)(lbl_803DD560 + 0x34) =
       (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - dVar4);
  *(float *)(lbl_803DD560 + 0x3c) =
       (float)((double)CONCAT44(0x43300000,param_6 ^ 0x80000000) - dVar4);
  *(float *)(lbl_803DD560 + 0x44) = (float)param_1;
  *(float *)(lbl_803DD560 + 0x5c) = lbl_803E1888;
  fVar1 = *(float *)(lbl_803DD560 + 0x14) - *(float *)(lbl_803DD560 + 0x10);
  fVar2 = *(float *)(lbl_803DD560 + 0x1c) - *(float *)(lbl_803DD560 + 0x18);
  fVar3 = *(float *)(lbl_803DD560 + 0x24) - *(float *)(lbl_803DD560 + 0x20);
  dVar4 = sqrtf((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  *(float *)(lbl_803DD560 + 0x60) = (float)dVar4;
  (**(code **)(*lbl_803DCA50 + 0x34))
            ((double)*(float *)(lbl_803DD560 + 0x60),(double)lbl_803E18B0,(double)lbl_803E18B4,
             (double)lbl_803E18B4,(double)lbl_803E18B8,lbl_803DD560 + 0x48);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010b428
 * EN v1.0 Address: 0x8010B428
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010B694
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010b428(void)
{
  FUN_80017814(lbl_803DD560);
  lbl_803DD560 = 0;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeTestStrength_func06_nop(void) {}

/* fn_X(lbl); lbl = 0; */
extern u32 lbl_803DD560;
extern void mm_free(u32);
#pragma scheduling off
#pragma peephole off
void CameraModeTestStrength_func05(void) { mm_free(lbl_803DD560); lbl_803DD560 = 0; }
#pragma peephole reset
#pragma scheduling reset
