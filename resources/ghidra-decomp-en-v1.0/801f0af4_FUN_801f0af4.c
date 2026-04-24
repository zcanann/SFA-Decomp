// Function: FUN_801f0af4
// Entry: 801f0af4
// Size: 84 bytes

void FUN_801f0af4(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca7c + 0x18))();
  if (*piVar1 != 0) {
    FUN_80054308();
    *piVar1 = 0;
  }
  return;
}

