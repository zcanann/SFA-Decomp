// Function: FUN_80234758
// Entry: 80234758
// Size: 72 bytes

void FUN_80234758(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*piVar1 != 0) {
    FUN_8001f384();
  }
  if (piVar1[1] != 0) {
    FUN_80054308();
  }
  return;
}

