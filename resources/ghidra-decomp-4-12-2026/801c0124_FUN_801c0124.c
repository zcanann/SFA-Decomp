// Function: FUN_801c0124
// Entry: 801c0124
// Size: 84 bytes

void FUN_801c0124(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 4);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

