// Function: FUN_80237244
// Entry: 80237244
// Size: 100 bytes

void FUN_80237244(int param_1)

{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  if (*puVar1 != 0) {
    FUN_8001f448(*puVar1);
  }
  FUN_8000b7dc(param_1,0x40);
  return;
}

