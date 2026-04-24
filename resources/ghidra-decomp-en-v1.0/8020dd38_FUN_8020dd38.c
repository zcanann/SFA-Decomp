// Function: FUN_8020dd38
// Entry: 8020dd38
// Size: 100 bytes

void FUN_8020dd38(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_8001f384();
    *piVar1 = 0;
  }
  (**(code **)(*DAT_803dca78 + 0x14))(param_1);
  return;
}

