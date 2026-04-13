// Function: FUN_801c0a7c
// Entry: 801c0a7c
// Size: 100 bytes

void FUN_801c0a7c(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 0x10);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

