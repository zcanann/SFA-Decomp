// Function: FUN_8016f030
// Entry: 8016f030
// Size: 112 bytes

void FUN_8016f030(int param_1)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0;
  puVar2 = *(uint **)(param_1 + 0xb8);
  do {
    FUN_800238c4(*puVar2);
    puVar2 = puVar2 + 6;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 3);
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

