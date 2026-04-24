// Function: FUN_801c3e4c
// Entry: 801c3e4c
// Size: 100 bytes

void FUN_801c3e4c(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca7c + 0x18))();
  FUN_80013e2c(DAT_803ddbb8);
  DAT_803ddbb8 = 0;
  if (*piVar1 != 0) {
    FUN_80054308();
  }
  *piVar1 = 0;
  return;
}

