// Function: FUN_801c4400
// Entry: 801c4400
// Size: 100 bytes

void FUN_801c4400(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6fc + 0x18))();
  FUN_80013e4c(DAT_803de838);
  DAT_803de838 = (undefined *)0x0;
  if (*piVar1 != 0) {
    FUN_80054484();
  }
  *piVar1 = 0;
  return;
}

