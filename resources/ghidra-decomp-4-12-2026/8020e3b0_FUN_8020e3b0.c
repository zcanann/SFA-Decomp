// Function: FUN_8020e3b0
// Entry: 8020e3b0
// Size: 100 bytes

void FUN_8020e3b0(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *puVar2 = 0;
  }
  (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
  return;
}

