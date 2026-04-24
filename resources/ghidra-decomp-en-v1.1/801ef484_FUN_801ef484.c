// Function: FUN_801ef484
// Entry: 801ef484
// Size: 148 bytes

void FUN_801ef484(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (*(int *)(iVar1 + 0x18) != 0) {
    FUN_80054484();
    *(undefined4 *)(iVar1 + 0x18) = 0;
  }
  if (*(int *)(iVar1 + 0x1c) != 0) {
    FUN_80054484();
    *(undefined4 *)(iVar1 + 0x1c) = 0;
  }
  FUN_80013e4c(*(undefined **)(iVar1 + 0x14));
  *(undefined4 *)(iVar1 + 0x14) = 0;
  FUN_8003709c(param_1,10);
  return;
}

