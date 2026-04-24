// Function: FUN_8011a914
// Entry: 8011a914
// Size: 316 bytes

void FUN_8011a914(int param_1)

{
  int iVar1;
  int *piVar2;
  
  if (DAT_8031a804 != 0) {
    FUN_80023800();
    DAT_8031a804 = 0;
  }
  DAT_803dd6a0 = 0;
  if (DAT_803db9fb != -1) {
    (**(code **)(*DAT_803dcaa0 + 8))();
    DAT_803db9fb = -1;
  }
  if (DAT_803dd6a8 != 0) {
    FUN_80023800();
    DAT_803dd6a8 = 0;
  }
  if (DAT_803dd6ac != 0) {
    FUN_80023800();
    DAT_803dd6ac = 0;
  }
  iVar1 = 0;
  piVar2 = &DAT_803a8680;
  do {
    if (*piVar2 != 0) {
      FUN_80054308();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  FUN_80054308(DAT_803dd6c8);
  if (param_1 != 0) {
    FUN_8001fee4();
  }
  if (DAT_803dd6b8 != 0) {
    (**(code **)(*DAT_803dcaa4 + 0x10))();
    DAT_803dd6b8 = 0;
  }
  return;
}

