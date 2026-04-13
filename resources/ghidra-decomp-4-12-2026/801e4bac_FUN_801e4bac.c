// Function: FUN_801e4bac
// Entry: 801e4bac
// Size: 84 bytes

void FUN_801e4bac(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  uVar1 = *(uint *)(iVar2 + 0x18);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *(undefined4 *)(iVar2 + 0x18) = 0;
  }
  return;
}

