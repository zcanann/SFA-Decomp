// Function: FUN_801eee4c
// Entry: 801eee4c
// Size: 148 bytes

void FUN_801eee4c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x18))();
  if (*(int *)(iVar1 + 0x18) != 0) {
    FUN_80054308();
    *(undefined4 *)(iVar1 + 0x18) = 0;
  }
  if (*(int *)(iVar1 + 0x1c) != 0) {
    FUN_80054308();
    *(undefined4 *)(iVar1 + 0x1c) = 0;
  }
  FUN_80013e2c(*(undefined4 *)(iVar1 + 0x14));
  *(undefined4 *)(iVar1 + 0x14) = 0;
  FUN_80036fa4(param_1,10);
  return;
}

