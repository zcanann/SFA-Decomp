#include "ghidra_import.h"
#include "main/dll/torch1D9.h"

extern undefined4 FUN_80006724();
extern undefined4 FUN_80006728();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a90();
extern undefined4 FUN_80017a98();
extern undefined8 FUN_80080f14();
extern undefined4 FUN_80080f18();
extern int FUN_800e8b98();

extern undefined4 DAT_8032768c;
extern undefined4 DAT_803276c4;
extern undefined4 DAT_803276fc;
extern undefined4 DAT_80327734;
extern undefined4* DAT_803dd72c;
extern f32 lbl_803E5F18;

/*
 * --INFO--
 *
 * Function: FUN_801d083c
 * EN v1.0 Address: 0x801D083C
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x801D0AB0
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d083c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  FUN_80017a98();
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x6000;
  uVar1 = FUN_80017690(0x19f);
  if (uVar1 == 0) {
    uVar1 = FUN_80017690(0x19d);
    if (uVar1 == 0) {
      *(undefined *)(pfVar3 + 1) = 0;
    }
    else {
      *(undefined *)(pfVar3 + 1) = 1;
    }
  }
  else {
    *(undefined *)(pfVar3 + 1) = 0xc;
  }
  *pfVar3 = lbl_803E5F18;
  FUN_80080f18(&DAT_803276c4,&DAT_8032768c,&DAT_803276fc,&DAT_80327734);
  iVar2 = FUN_800e8b98();
  if (iVar2 == 0) {
    uVar4 = FUN_80080f14(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
    FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  else {
    uVar4 = FUN_80080f14(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
    FUN_80006724(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  (**(code **)(*DAT_803dd72c + 0x50))(7,0,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,2,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,5,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,10,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,0x1c,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,9,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0b54
 * EN v1.0 Address: 0x801D0B54
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801D0C74
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0b54(int param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar2 = FUN_80017a90();
  if (iVar2 != 0) {
    bVar1 = *pbVar4;
    if (bVar1 == 2) {
      iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x38))(iVar2,param_1);
      if (iVar2 != 0) {
        *pbVar4 = 3;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        uVar3 = FUN_80017690(0x94);
        if (uVar3 != 0) {
          FUN_80017698(0x4e4,0);
          FUN_80017698(0x4e5,0);
          FUN_80017698(0xc11,1);
          *pbVar4 = 1;
        }
      }
      else {
        *pbVar4 = 2;
      }
    }
    else if (((bVar1 != 4) && (bVar1 < 4)) && (uVar3 = FUN_80017690(0xbf), uVar3 != 0)) {
      FUN_80017698(0x4e4,1);
      FUN_80017698(0x4e5,1);
      FUN_80017698(0xc11,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d0c68
 * EN v1.0 Address: 0x801D0C68
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801D0D90
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d0c68(int param_1)
{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0xb8);
  uVar1 = FUN_80017690(0xbf);
  if (uVar1 == 0) {
    *puVar2 = 0;
  }
  else {
    uVar1 = FUN_80017690(0x4e4);
    if (uVar1 == 0) {
      FUN_80017698(0xbf,0);
    }
    else {
      *puVar2 = 4;
    }
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}
