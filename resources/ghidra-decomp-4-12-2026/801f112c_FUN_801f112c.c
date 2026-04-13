// Function: FUN_801f112c
// Entry: 801f112c
// Size: 84 bytes

void FUN_801f112c(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6fc + 0x18))();
  if (*piVar1 != 0) {
    FUN_80054484();
    *piVar1 = 0;
  }
  return;
}

