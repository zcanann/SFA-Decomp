// Function: FUN_80179518
// Entry: 80179518
// Size: 356 bytes

void FUN_80179518(undefined2 *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar3 + 0x21) = 0;
  if (*(int *)(param_1 + 0x7a) == 0) {
    iVar1 = *(int *)(param_1 + 0x26);
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0x10);
    *param_1 = (short)((int)*(char *)(iVar1 + 0x18) << 8);
    if (param_1[0x23] == 0x151) {
      uVar2 = FUN_80020078(*(uint *)(iVar3 + 0x10));
      if (uVar2 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0x75);
        *(undefined *)(iVar3 + 0x21) = 1;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    else if (param_1[0x23] == 0x37a) {
      uVar2 = FUN_80020078(*(uint *)(iVar3 + 0x10));
      if (uVar2 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0x8a);
        *(undefined *)(iVar3 + 0x21) = 1;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

