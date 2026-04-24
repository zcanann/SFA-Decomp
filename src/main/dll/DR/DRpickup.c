#include "ghidra_import.h"
#include "main/dll/DR/DRpickup.h"

extern undefined4 FUN_80014acc();
extern uint FUN_80022264();
extern double FUN_80247f54();
extern double FUN_80293900();

extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e6798;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6780;
extern f32 FLOAT_803e6784;
extern f32 FLOAT_803e6790;
extern f32 FLOAT_803e67b4;
extern f32 FLOAT_803e67b8;
extern f32 FLOAT_803e67c4;
extern f32 FLOAT_803e67cc;
extern f32 FLOAT_803e6820;
extern f32 FLOAT_803e6854;
extern f32 FLOAT_803e685c;
extern f32 FLOAT_803e6870;
extern f32 FLOAT_803e6874;
extern f32 FLOAT_803e6878;
extern f32 FLOAT_803e687c;
extern f32 FLOAT_803e6880;
extern f32 FLOAT_803e6884;
extern f32 FLOAT_803e6888;
extern f32 FLOAT_803e688c;
extern f32 FLOAT_803e6890;
extern f32 FLOAT_803e6894;
extern f32 FLOAT_803e6898;
extern f32 FLOAT_803e689c;
extern f32 FLOAT_803e68a0;
extern f32 FLOAT_803e68a4;
extern f32 FLOAT_803e68a8;
extern f32 FLOAT_803e68ac;

/*
 * --INFO--
 *
 * Function: FUN_801ec398
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801EC398
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ec398(int param_1,int param_2)
{
  byte bVar1;
  float fVar2;
  short sVar3;
  float fVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined2 local_a8;
  undefined2 local_a6;
  undefined2 local_a4;
  float local_a0;
  undefined4 local_9c;
  float local_98;
  undefined4 local_94;
  undefined4 local_90;
  uint uStack_8c;
  
  dVar5 = FUN_80293900((double)(*(float *)(param_2 + 0x49c) * *(float *)(param_2 + 0x49c) +
                               *(float *)(param_2 + 0x494) * *(float *)(param_2 + 0x494) +
                               *(float *)(param_2 + 0x498) * *(float *)(param_2 + 0x498)));
  *(float *)(param_2 + 0x43c) = *(float *)(param_2 + 0x43c) - FLOAT_803dc074;
  fVar2 = *(float *)(param_2 + 0x43c);
  fVar4 = FLOAT_803e6780;
  if ((FLOAT_803e6780 <= fVar2) && (fVar4 = fVar2, FLOAT_803e67b4 < fVar2)) {
    fVar4 = FLOAT_803e67b4;
  }
  *(float *)(param_2 + 0x43c) = fVar4;
  if ((char)*(byte *)(param_2 + 0x428) < '\0') {
    dVar13 = (double)*(float *)(param_2 + 0x578);
    dVar11 = (double)*(float *)(param_2 + 0x574);
    dVar12 = (double)*(float *)(param_2 + 0x56c);
    dVar10 = (double)*(float *)(param_2 + 0x57c);
    dVar9 = (double)*(float *)(param_2 + 0x580);
    dVar8 = (double)FLOAT_803e67b8;
    dVar7 = (double)FLOAT_803e6790;
  }
  else {
    bVar1 = *(byte *)(param_2 + 0x4b4);
    if (bVar1 == 9) {
      dVar13 = (double)FLOAT_803e6884;
      dVar11 = (double)FLOAT_803e688c;
      dVar12 = (double)FLOAT_803e6898;
      dVar10 = (double)FLOAT_803e689c;
      dVar9 = (double)FLOAT_803e68a0;
      dVar8 = (double)FLOAT_803e67b8;
      dVar7 = (double)FLOAT_803e68a4;
      if ((double)FLOAT_803e67cc < dVar5) {
        local_a0 = FLOAT_803e6784;
        local_a4 = 0;
        local_a6 = 0;
        local_a8 = 0;
        local_9c = *(undefined4 *)(param_1 + 0xc);
        local_98 = FLOAT_803e68a8 + *(float *)(param_1 + 0x10);
        local_94 = *(undefined4 *)(param_1 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x80a,&local_a8,1,0xffffffff,0);
      }
    }
    else if ((bVar1 < 9) || (bVar1 != 0xd)) {
      dVar13 = (double)FLOAT_803e6888;
      dVar11 = (double)FLOAT_803e688c;
      dVar12 = (double)FLOAT_803e6890;
      dVar10 = (double)FLOAT_803e6894;
      dVar9 = (double)FLOAT_803e687c;
      dVar8 = (double)FLOAT_803e6880;
      dVar7 = (double)FLOAT_803e6790;
    }
    else {
      dVar13 = (double)FLOAT_803e6870;
      dVar11 = (double)FLOAT_803e6874;
      dVar12 = (double)FLOAT_803e6820;
      dVar10 = (double)FLOAT_803e6878;
      dVar9 = (double)FLOAT_803e687c;
      dVar8 = (double)FLOAT_803e6880;
      dVar7 = (double)FLOAT_803e6790;
      if (((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) &&
         (*(float *)(param_2 + 0x43c) <= FLOAT_803e6780)) {
        uStack_8c = FUN_80022264(5,10);
        uStack_8c = uStack_8c ^ 0x80000000;
        local_90 = 0x43300000;
        *(float *)(param_2 + 0x43c) =
             (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e6798);
        dVar6 = FUN_80247f54((float *)(param_1 + 0x24));
        if ((double)FLOAT_803e685c < dVar6) {
          uStack_8c = FUN_80022264(1,3);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          FUN_80014acc((double)(float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e6798));
        }
      }
      if ((double)FLOAT_803e6884 < dVar5) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x80b,0,2,0xffffffff,0);
      }
    }
    sVar3 = *(short *)(param_2 + 0x44c);
    if (((0x1d < sVar3) && (sVar3 < 0x3d)) || ((299 < sVar3 && (sVar3 < 0x14b)))) {
      dVar13 = (double)(float)(dVar13 * (double)FLOAT_803e67b8);
      dVar11 = (double)(float)(dVar11 * (double)FLOAT_803e67c4);
      dVar5 = (double)(float)(dVar12 + (double)FLOAT_803e67b8);
      dVar12 = (double)FLOAT_803e6780;
      if ((dVar12 <= dVar5) && (dVar12 = dVar5, (double)FLOAT_803e6820 < dVar5)) {
        dVar12 = (double)FLOAT_803e6820;
      }
    }
  }
  if ((*(byte *)(param_2 + 0x428) >> 1 & 1) != 0) {
    dVar13 = (double)FLOAT_803e6790;
  }
  dVar5 = (double)FLOAT_803e6870;
  if ((dVar5 <= dVar13) && (dVar5 = dVar13, (double)FLOAT_803e6784 < dVar13)) {
    dVar5 = (double)FLOAT_803e6784;
  }
  *(float *)(param_2 + 0x558) =
       (float)((double)FLOAT_803dc074 *
               (double)(FLOAT_803e68ac * (float)(dVar5 - (double)*(float *)(param_2 + 0x558))) +
              (double)*(float *)(param_2 + 0x558));
  *(float *)(param_2 + 0x534) =
       (float)((double)FLOAT_803dc074 *
               (double)(FLOAT_803e6854 * (float)(dVar11 - (double)*(float *)(param_2 + 0x534))) +
              (double)*(float *)(param_2 + 0x534));
  *(float *)(param_2 + 0x530) =
       (float)((double)FLOAT_803dc074 *
               (double)(FLOAT_803e68ac * (float)(dVar12 - (double)*(float *)(param_2 + 0x530))) +
              (double)*(float *)(param_2 + 0x530));
  fVar2 = FLOAT_803e67b8;
  *(float *)(param_2 + 0x548) =
       (float)((double)FLOAT_803dc074 *
               (double)(FLOAT_803e67b8 * (float)(dVar10 - (double)*(float *)(param_2 + 0x548))) +
              (double)*(float *)(param_2 + 0x548));
  *(float *)(param_2 + 0x54c) =
       (float)((double)FLOAT_803dc074 *
               (double)(fVar2 * (float)(dVar9 - (double)*(float *)(param_2 + 0x54c))) +
              (double)*(float *)(param_2 + 0x54c));
  *(float *)(param_2 + 0x540) =
       (float)((double)FLOAT_803dc074 *
               (double)(fVar2 * (float)(dVar8 - (double)*(float *)(param_2 + 0x540))) +
              (double)*(float *)(param_2 + 0x540));
  *(float *)(param_2 + 0x544) =
       (float)((double)FLOAT_803dc074 *
               (double)(fVar2 * (float)(dVar7 - (double)*(float *)(param_2 + 0x544))) +
              (double)*(float *)(param_2 + 0x544));
  return;
}
