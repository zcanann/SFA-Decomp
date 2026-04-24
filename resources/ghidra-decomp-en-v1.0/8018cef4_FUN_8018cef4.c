// Function: FUN_8018cef4
// Entry: 8018cef4
// Size: 76 bytes

void FUN_8018cef4(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x18))();
  if (*piVar1 != 0) {
    FUN_8001f384();
  }
  return;
}

