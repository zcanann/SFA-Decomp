#include "ghidra_import.h"
#include "main/dll/torch1D9.h"

extern undefined4 FUN_80006724();
extern undefined4 FUN_80006728();
extern uint FUN_80017690();
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
 * Function: edibleMushroomFn_801d083c
 * EN v1.0 Address: 0x801D083C
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x801D0AB0
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void edibleMushroomFn_801d083c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
