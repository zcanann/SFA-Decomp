// Function: FUN_801f39fc
// Entry: 801f39fc
// Size: 76 bytes

void FUN_801f39fc(int param_1)

{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (*puVar1 != 0) {
    FUN_8001f448(*puVar1);
  }
  return;
}

