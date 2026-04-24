// Function: FUN_8017906c
// Entry: 8017906c
// Size: 356 bytes

void FUN_8017906c(undefined2 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 0x21) = 0;
  if (*(int *)(param_1 + 0x7a) == 0) {
    iVar1 = *(int *)(param_1 + 0x26);
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0x10);
    *param_1 = (short)((int)*(char *)(iVar1 + 0x18) << 8);
    if (param_1[0x23] == 0x151) {
      iVar1 = FUN_8001ffb4(*(undefined4 *)(iVar2 + 0x10));
      if (iVar1 != 0) {
        (**(code **)(*DAT_803dca54 + 0x54))(param_1,0x75);
        *(undefined *)(iVar2 + 0x21) = 1;
      }
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
    else if (param_1[0x23] == 0x37a) {
      iVar1 = FUN_8001ffb4(*(undefined4 *)(iVar2 + 0x10));
      if (iVar1 != 0) {
        (**(code **)(*DAT_803dca54 + 0x54))(param_1,0x8a);
        *(undefined *)(iVar2 + 0x21) = 1;
      }
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
    else {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

