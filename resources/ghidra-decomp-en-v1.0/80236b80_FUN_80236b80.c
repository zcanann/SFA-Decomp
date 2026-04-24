// Function: FUN_80236b80
// Entry: 80236b80
// Size: 100 bytes

void FUN_80236b80(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca78 + 0x14))();
  if (*piVar1 != 0) {
    FUN_8001f384();
  }
  FUN_8000b7bc(param_1,0x40);
  return;
}

