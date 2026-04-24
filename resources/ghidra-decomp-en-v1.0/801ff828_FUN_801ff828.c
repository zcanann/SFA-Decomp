// Function: FUN_801ff828
// Entry: 801ff828
// Size: 84 bytes

void FUN_801ff828(int param_1)

{
  int iVar1;
  
  FUN_801fe31c(param_1,*(undefined4 *)(param_1 + 0xb8));
  FUN_80037964(param_1,8);
  iVar1 = *(int *)(param_1 + 100);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x4008;
  }
  return;
}

