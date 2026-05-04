#include "ghidra_import.h"
#include "main/dll/DR/DRpickup.h"

extern undefined4 FUN_80006b94();
extern uint FUN_80017760();
extern double FUN_80247f54();
extern double FUN_80293900();

extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e6798;
extern f32 lbl_803DC074;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6790;
extern f32 lbl_803E67B4;
extern f32 lbl_803E67B8;
extern f32 lbl_803E67C4;
extern f32 lbl_803E67CC;
extern f32 lbl_803E6820;
extern f32 lbl_803E6854;
extern f32 lbl_803E685C;
extern f32 lbl_803E6870;
extern f32 lbl_803E6874;
extern f32 lbl_803E6878;
extern f32 lbl_803E687C;
extern f32 lbl_803E6880;
extern f32 lbl_803E6884;
extern f32 lbl_803E6888;
extern f32 lbl_803E688C;
extern f32 lbl_803E6890;
extern f32 lbl_803E6894;
extern f32 lbl_803E6898;
extern f32 lbl_803E689C;
extern f32 lbl_803E68A0;
extern f32 lbl_803E68A4;
extern f32 lbl_803E68A8;
extern f32 lbl_803E68AC;

/*
 * --INFO--
 *
 * Function: FUN_801ec1ac
 * EN v1.0 Address: 0x801EC1AC
 * EN v1.0 Size: 1096b
 * EN v1.1 Address: 0x801EC398
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ec1ac(int param_1,int param_2)
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
  *(float *)(param_2 + 0x43c) = *(float *)(param_2 + 0x43c) - lbl_803DC074;
  fVar2 = *(float *)(param_2 + 0x43c);
  fVar4 = lbl_803E6780;
  if ((lbl_803E6780 <= fVar2) && (fVar4 = fVar2, lbl_803E67B4 < fVar2)) {
    fVar4 = lbl_803E67B4;
  }
  *(float *)(param_2 + 0x43c) = fVar4;
  if ((char)*(byte *)(param_2 + 0x428) < '\0') {
    dVar13 = (double)*(float *)(param_2 + 0x578);
    dVar11 = (double)*(float *)(param_2 + 0x574);
    dVar12 = (double)*(float *)(param_2 + 0x56c);
    dVar10 = (double)*(float *)(param_2 + 0x57c);
    dVar9 = (double)*(float *)(param_2 + 0x580);
    dVar8 = (double)lbl_803E67B8;
    dVar7 = (double)lbl_803E6790;
  }
  else {
    bVar1 = *(byte *)(param_2 + 0x4b4);
    if (bVar1 == 9) {
      dVar13 = (double)lbl_803E6884;
      dVar11 = (double)lbl_803E688C;
      dVar12 = (double)lbl_803E6898;
      dVar10 = (double)lbl_803E689C;
      dVar9 = (double)lbl_803E68A0;
      dVar8 = (double)lbl_803E67B8;
      dVar7 = (double)lbl_803E68A4;
      if ((double)lbl_803E67CC < dVar5) {
        local_a0 = lbl_803E6784;
        local_a4 = 0;
        local_a6 = 0;
        local_a8 = 0;
        local_9c = *(undefined4 *)(param_1 + 0xc);
        local_98 = lbl_803E68A8 + *(float *)(param_1 + 0x10);
        local_94 = *(undefined4 *)(param_1 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x80a,&local_a8,1,0xffffffff,0);
      }
    }
    else if ((bVar1 < 9) || (bVar1 != 0xd)) {
      dVar13 = (double)lbl_803E6888;
      dVar11 = (double)lbl_803E688C;
      dVar12 = (double)lbl_803E6890;
      dVar10 = (double)lbl_803E6894;
      dVar9 = (double)lbl_803E687C;
      dVar8 = (double)lbl_803E6880;
      dVar7 = (double)lbl_803E6790;
    }
    else {
      dVar13 = (double)lbl_803E6870;
      dVar11 = (double)lbl_803E6874;
      dVar12 = (double)lbl_803E6820;
      dVar10 = (double)lbl_803E6878;
      dVar9 = (double)lbl_803E687C;
      dVar8 = (double)lbl_803E6880;
      dVar7 = (double)lbl_803E6790;
      if (((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) &&
         (*(float *)(param_2 + 0x43c) <= lbl_803E6780)) {
        uStack_8c = FUN_80017760(5,10);
        uStack_8c = uStack_8c ^ 0x80000000;
        local_90 = 0x43300000;
        *(float *)(param_2 + 0x43c) =
             (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e6798);
        dVar6 = FUN_80247f54((float *)(param_1 + 0x24));
        if ((double)lbl_803E685C < dVar6) {
          uStack_8c = FUN_80017760(1,3);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          FUN_80006b94((double)(float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e6798));
        }
      }
      if ((double)lbl_803E6884 < dVar5) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x80b,0,2,0xffffffff,0);
      }
    }
    sVar3 = *(short *)(param_2 + 0x44c);
    if (((0x1d < sVar3) && (sVar3 < 0x3d)) || ((299 < sVar3 && (sVar3 < 0x14b)))) {
      dVar13 = (double)(float)(dVar13 * (double)lbl_803E67B8);
      dVar11 = (double)(float)(dVar11 * (double)lbl_803E67C4);
      dVar5 = (double)(float)(dVar12 + (double)lbl_803E67B8);
      dVar12 = (double)lbl_803E6780;
      if ((dVar12 <= dVar5) && (dVar12 = dVar5, (double)lbl_803E6820 < dVar5)) {
        dVar12 = (double)lbl_803E6820;
      }
    }
  }
  if ((*(byte *)(param_2 + 0x428) >> 1 & 1) != 0) {
    dVar13 = (double)lbl_803E6790;
  }
  dVar5 = (double)lbl_803E6870;
  if ((dVar5 <= dVar13) && (dVar5 = dVar13, (double)lbl_803E6784 < dVar13)) {
    dVar5 = (double)lbl_803E6784;
  }
  *(float *)(param_2 + 0x558) =
       (float)((double)lbl_803DC074 *
               (double)(lbl_803E68AC * (float)(dVar5 - (double)*(float *)(param_2 + 0x558))) +
              (double)*(float *)(param_2 + 0x558));
  *(float *)(param_2 + 0x534) =
       (float)((double)lbl_803DC074 *
               (double)(lbl_803E6854 * (float)(dVar11 - (double)*(float *)(param_2 + 0x534))) +
              (double)*(float *)(param_2 + 0x534));
  *(float *)(param_2 + 0x530) =
       (float)((double)lbl_803DC074 *
               (double)(lbl_803E68AC * (float)(dVar12 - (double)*(float *)(param_2 + 0x530))) +
              (double)*(float *)(param_2 + 0x530));
  fVar2 = lbl_803E67B8;
  *(float *)(param_2 + 0x548) =
       (float)((double)lbl_803DC074 *
               (double)(lbl_803E67B8 * (float)(dVar10 - (double)*(float *)(param_2 + 0x548))) +
              (double)*(float *)(param_2 + 0x548));
  *(float *)(param_2 + 0x54c) =
       (float)((double)lbl_803DC074 *
               (double)(fVar2 * (float)(dVar9 - (double)*(float *)(param_2 + 0x54c))) +
              (double)*(float *)(param_2 + 0x54c));
  *(float *)(param_2 + 0x540) =
       (float)((double)lbl_803DC074 *
               (double)(fVar2 * (float)(dVar8 - (double)*(float *)(param_2 + 0x540))) +
              (double)*(float *)(param_2 + 0x540));
  *(float *)(param_2 + 0x544) =
       (float)((double)lbl_803DC074 *
               (double)(fVar2 * (float)(dVar7 - (double)*(float *)(param_2 + 0x544))) +
              (double)*(float *)(param_2 + 0x544));
  return;
}
