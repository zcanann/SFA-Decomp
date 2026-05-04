#include "ghidra_import.h"
#include "main/dll/DR/DRshackle.h"

extern bool FUN_800067f0();
extern undefined4 FUN_80006814();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern undefined4 FUN_80081108();
extern undefined4 FUN_801e9c00();

extern undefined4 DAT_803adcf4;
extern undefined4 DAT_803add04;
extern undefined4 DAT_803dcd24;
extern undefined4* DAT_803dd6ec;
extern f64 DOUBLE_803e6798;
extern f32 lbl_803DC074;
extern f32 lbl_803DCD48;
extern f32 lbl_803DE8E4;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6790;
extern f32 lbl_803E67A0;
extern f32 lbl_803E67A4;
extern f32 lbl_803E67A8;
extern f32 lbl_803E67AC;
extern f32 lbl_803E67B0;
extern f32 lbl_803E67B4;
extern f32 lbl_803E67B8;
extern f32 lbl_803E67BC;
extern f32 lbl_803E67C0;
extern f32 lbl_803E67C4;
extern f32 lbl_803E67C8;
extern f32 lbl_803E67CC;
extern f32 lbl_803E67D0;
extern f32 lbl_803E67D4;
extern f32 lbl_803E67D8;
extern f32 lbl_803E67DC;
extern f32 lbl_803E67E0;
extern f32 lbl_803E67F0;
extern f32 lbl_803E67F8;
extern f32 lbl_803E67FC;

/*
 * --INFO--
 *
 * Function: FUN_801ea854
 * EN v1.0 Address: 0x801EA854
 * EN v1.0 Size: 1060b
 * EN v1.1 Address: 0x801EA878
 * EN v1.1 Size: 1080b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ea854(double param_1,uint param_2,int param_3,uint param_4,undefined4 param_5,
                 uint param_6)
{
  float fVar1;
  int iVar2;
  bool bVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  undefined8 local_28;
  
  dVar6 = (double)lbl_803E6780;
  if ((dVar6 <= param_1) && (dVar6 = param_1, (double)lbl_803E67A0 < param_1)) {
    dVar6 = (double)lbl_803E67A0;
  }
  if (((param_6 & 1) != 0) && (bVar3 = FUN_800067f0(param_2,8), bVar3)) {
    lbl_803DE8E4 = (float)((double)lbl_803E67A4 * dVar6);
    if (lbl_803DE8E4 < lbl_803E6780) {
      lbl_803DE8E4 = -lbl_803DE8E4;
    }
    if (lbl_803DE8E4 < lbl_803E67A8) {
      lbl_803DE8E4 = lbl_803E67A8;
    }
    if (lbl_803E67AC < lbl_803DE8E4) {
      lbl_803DE8E4 = lbl_803E67AC;
    }
    if (lbl_803E67B0 <= *(float *)(param_3 + 0x424)) {
      iVar2 = 0;
    }
    else {
      iVar2 = (int)((double)lbl_803E67B4 * dVar6);
      if (iVar2 < 0) {
        iVar2 = -iVar2;
      }
      if (0x7f < iVar2) {
        iVar2 = 0x7f;
      }
    }
    FUN_80006814((double)(lbl_803E67B8 + lbl_803DE8E4 / lbl_803E67A0),param_2,8,(byte)iVar2);
  }
  if ((((param_6 & 2) != 0) && (bVar3 = FUN_800067f0(param_2,1), bVar3)) &&
     (*(float *)(param_3 + 0x424) < lbl_803E67B0)) {
    dVar5 = (double)lbl_803E6780;
    if (dVar5 != dVar6) {
      local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 4) ^ 0x80000000);
      dVar5 = (double)((float)(dVar6 * (double)(float)(local_30 - DOUBLE_803e6798)) / lbl_803E67BC
                      );
    }
    lbl_803DE8E4 = (float)dVar5;
    fVar1 = (float)dVar5;
    if (lbl_803E6780 <= fVar1) {
      if (lbl_803E6784 < fVar1) {
        lbl_803DE8E4 = lbl_803E6784;
      }
    }
    else {
      lbl_803DE8E4 = -fVar1;
    }
    uVar4 = (uint)(lbl_803E67C0 * lbl_803DE8E4);
    local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    if ((float)(local_28 - DOUBLE_803e6798) <= lbl_803E67C0) {
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      if ((float)(local_28 - DOUBLE_803e6798) < lbl_803E6780) {
        uVar4 = 0;
      }
    }
    else {
      uVar4 = 0x7f;
    }
    FUN_80006814((double)(lbl_803E67B8 + lbl_803DE8E4),param_2,1,(byte)uVar4);
  }
  if ((param_6 & 4) != 0) {
    FUN_80006824(param_2,*(ushort *)(param_3 + 0x440));
    FUN_80006824(param_2,0x11b);
    if ((int)param_4 < 6) {
      if (lbl_803E67A8 < *(float *)(param_3 + 0x3f8)) {
        *(float *)(param_3 + 0x3f8) =
             -(lbl_803E67C4 * lbl_803DC074 - *(float *)(param_3 + 0x3f8));
      }
    }
    else {
      *(float *)(param_3 + 0x3f8) = *(float *)(param_3 + 0x3f8) + lbl_803DC074;
    }
    if (lbl_803E67A0 < *(float *)(param_3 + 0x3f8)) {
      *(float *)(param_3 + 0x3f8) = lbl_803E67A0;
    }
    if (*(float *)(param_3 + 0x3f8) < lbl_803E67C8) {
      *(float *)(param_3 + 0x3f8) = lbl_803E67C8;
    }
    FUN_80006814((double)(*(float *)(param_3 + 0x3f8) * lbl_803E67D0 + lbl_803E67CC),param_2,2,
                 (byte)(int)*(float *)(param_3 + 0x3f8));
    if ((int)param_4 < 6) {
      if (lbl_803E67D4 < *(float *)(param_3 + 0x3f4)) {
        *(float *)(param_3 + 0x3f4) =
             -(lbl_803E6790 * lbl_803DC074 - *(float *)(param_3 + 0x3f4));
      }
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,param_4 ^ 0x80000000);
      *(float *)(param_3 + 0x3f4) = lbl_803E67D4 + (float)(local_28 - DOUBLE_803e6798);
    }
    if (lbl_803E67D8 < *(float *)(param_3 + 0x3f4)) {
      *(float *)(param_3 + 0x3f4) = lbl_803E67D8;
    }
    if (*(float *)(param_3 + 0x3f4) < lbl_803E67DC) {
      *(float *)(param_3 + 0x3f4) = lbl_803E67DC;
    }
    FUN_80006814((double)(*(float *)(param_3 + 0x3f4) / lbl_803E67E0),param_2,4,
                 (byte)(int)*(float *)(param_3 + 0x3f4));
    FUN_80081108((double)lbl_803E6790,(double)(*(float *)(param_3 + 0x3f4) / lbl_803E67F0));
    FUN_80081108((double)lbl_803E6790,(double)(*(float *)(param_3 + 0x3f4) / lbl_803E67F0));
  }
  FUN_801e9c00();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801eac78
 * EN v1.0 Address: 0x801EAC78
 * EN v1.0 Size: 528b
 * EN v1.1 Address: 0x801EACB0
 * EN v1.1 Size: 476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_801eac78(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  double in_f30;
  double in_f31;
  
  if ((DAT_803dcd24 == -1) ||
     (iVar3 = (**(code **)(*DAT_803dd6ec + 0x34))(param_2 + 0x28), iVar3 < DAT_803dcd24)) {
    if (DAT_803dcd24 == -1) {
      iVar3 = FUN_80017a98();
      dVar4 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
      fVar1 = (float)(dVar4 * (double)lbl_803E6790);
    }
    else {
      in_f31 = (double)(lbl_803E67E0 *
                        (float)((double)CONCAT44(0x43300000,DAT_803add04 ^ 0x80000000) -
                               DOUBLE_803e6798) + lbl_803E67E0 * DAT_803adcf4);
      in_f30 = (double)(lbl_803E67E0 *
                        (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x44) ^ 0x80000000)
                               - DOUBLE_803e6798) + lbl_803E67E0 * *(float *)(param_2 + 0x34));
      fVar1 = (float)(in_f31 - in_f30);
      if (fVar1 < lbl_803E6780) {
        fVar1 = -fVar1;
      }
    }
    fVar2 = *(float *)(param_2 + 0x1c);
    if (fVar2 < fVar1) {
      if (fVar1 < *(float *)(param_2 + 0x18)) {
        dVar4 = (double)(((fVar1 - fVar2) / (*(float *)(param_2 + 0x18) - fVar2)) *
                         (*(float *)(param_2 + 0x20) - *(float *)(param_2 + 0x24)) +
                        *(float *)(param_2 + 0x24));
      }
      else {
        dVar4 = (double)*(float *)(param_2 + 0x20);
      }
    }
    else {
      dVar4 = (double)*(float *)(param_2 + 0x24);
    }
    if (*(char *)(param_2 + 0x434) == '\0') {
      fVar1 = (float)(in_f30 - in_f31);
      if (fVar1 < lbl_803E6780) {
        fVar1 = -fVar1;
      }
      if (lbl_803DCD48 < fVar1) {
        dVar4 = (double)lbl_803E6780;
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dd6ec + 0x34))(param_2 + 0x28);
    if (iVar3 == 2) {
      dVar4 = (double)lbl_803E67F8;
    }
    else {
      dVar4 = (double)lbl_803E67FC;
    }
  }
  return dVar4;
}
