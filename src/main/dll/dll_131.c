#include "ghidra_import.h"
#include "main/dll/dll_131.h"

extern undefined4 FUN_800033a8();
extern uint FUN_80017760();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8003b818();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3ce8;
extern f64 DOUBLE_803e3d00;
extern f64 DOUBLE_803e3d08;
extern f32 lbl_803DC074;
extern f32 lbl_803E3C74;
extern f32 lbl_803E3C8C;
extern f32 lbl_803E3CE0;
extern f32 lbl_803E3CF8;

/*
 * --INFO--
 *
 * Function: FUN_80167764
 * EN v1.0 Address: 0x80167764
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801678A4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80167764(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)
{
  float fVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  uVar5 = 6;
  if (param_11 != 0) {
    uVar5 = 7;
  }
  uVar2 = 5;
  uVar3 = 1;
  uVar4 = 0x108;
  iVar6 = *DAT_803dd738;
  (**(code **)(iVar6 + 0x58))((double)lbl_803E3CE0,param_9,param_10,iVar8);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  iVar7 = *(int *)(iVar8 + 0x40c);
  FUN_800033a8(iVar7,0,0x94);
  *(undefined *)(iVar7 + 0x90) = 5;
  *(byte *)(iVar7 + 0x92) = *(byte *)(iVar7 + 0x92) & 0xf | 0x30;
  fVar1 = lbl_803E3C74;
  dVar9 = (double)lbl_803E3C74;
  *(float *)(iVar7 + 0x7c) = lbl_803E3C74;
  *(float *)(iVar7 + 0x80) = lbl_803E3C8C;
  *(float *)(iVar7 + 0x84) = fVar1;
  *(float *)(iVar7 + 0x88) = -*(float *)(param_9 + 0x10);
  *(undefined4 *)(iVar7 + 0x70) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(iVar7 + 0x74) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(iVar7 + 0x78) = *(undefined4 *)(param_9 + 0x14);
  FUN_800305f8(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,uVar2,uVar3
               ,uVar4,uVar5,iVar6);
  *(ushort *)(iVar8 + 0x274) = (ushort)(*(char *)(param_10 + 0x2b) != '\0');
  *(undefined2 *)(iVar8 + 0x270) = 0;
  *(undefined2 *)(iVar8 + 0x402) = 0;
  *(undefined *)(iVar8 + 0x405) = 0;
  *(undefined *)(iVar8 + 0x25f) = 0;
  ObjHits_DisableObject(param_9);
  fVar1 = lbl_803E3C8C;
  *(float *)(iVar7 + 4) = lbl_803E3C8C;
  *(float *)(iVar7 + 0x18) = fVar1;
  *(float *)(iVar7 + 0x2c) = fVar1;
  *(float *)(iVar7 + 0x40) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016793c
 * EN v1.0 Address: 0x8016793C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801679FC
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016793c(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0x14))(param_1,*(undefined4 *)(param_1 + 0xb8),2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80167978
 * EN v1.0 Address: 0x80167978
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80167A8C
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80167978(int param_1,float *param_2,byte *param_3)
{
  double dVar1;
  byte *pbVar2;
  
  dVar1 = DOUBLE_803e3ce8;
  pbVar2 = *(byte **)(param_1 + 0xb8);
  *param_2 = *(float *)(param_1 + 0x18) -
             (float)((double)CONCAT44(0x43300000,(uint)*pbVar2) - DOUBLE_803e3ce8);
  param_2[1] = *(float *)(param_1 + 0x18) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[1]) - dVar1);
  param_2[2] = *(float *)(param_1 + 0x20) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[2]) - dVar1);
  param_2[3] = *(float *)(param_1 + 0x20) -
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[3]) - dVar1);
  param_2[4] = *(float *)(param_1 + 0x1c) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[4]) - dVar1);
  param_2[5] = *(float *)(param_1 + 0x1c) -
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[5]) - dVar1);
  *param_3 = pbVar2[6];
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80167aa0
 * EN v1.0 Address: 0x80167AA0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80167B80
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80167aa0(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80167ad4
 * EN v1.0 Address: 0x80167AD4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x80167C10
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80167ad4(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if ((*(short *)(param_2 + 0x274) == 2) &&
     (*(float *)(iVar3 + 0x34) = *(float *)(iVar3 + 0x34) - lbl_803DC074,
     *(float *)(iVar3 + 0x34) <= lbl_803E3CF8)) {
    *(undefined *)(param_2 + 0x346) = 1;
  }
  if ((*(char *)(param_2 + 0x346) != '\0') || (*(char *)(param_2 + 0x27b) != '\0')) {
    iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                      ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x3fe))
                                      - DOUBLE_803e3d00),param_1,param_2,1);
    if (iVar2 != 0) {
      return 5;
    }
    iVar2 = *(int *)(param_1 + 0x4c);
    uVar1 = FUN_80017760(0,99);
    if ((int)uVar1 < (int)(uint)*(byte *)(iVar2 + 0x2f)) {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,3);
    }
    else {
      uVar1 = FUN_80017760(300,600);
      *(float *)(iVar3 + 0x34) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3d08);
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
    }
  }
  return 0;
}
