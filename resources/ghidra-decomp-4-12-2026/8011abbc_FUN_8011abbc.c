// Function: FUN_8011abbc
// Entry: 8011abbc
// Size: 316 bytes

void FUN_8011abbc(int param_1)

{
  int iVar1;
  int *piVar2;
  
  if (DAT_8031b454 != 0) {
    FUN_800238c4(DAT_8031b454);
    DAT_8031b454 = 0;
  }
  DAT_803de320 = 0;
  if (DAT_803dc65b != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
    DAT_803dc65b = -1;
  }
  if (DAT_803de328 != 0) {
    FUN_800238c4(DAT_803de328);
    DAT_803de328 = 0;
  }
  if (DAT_803de32c != 0) {
    FUN_800238c4(DAT_803de32c);
    DAT_803de32c = 0;
  }
  iVar1 = 0;
  piVar2 = &DAT_803a92e0;
  do {
    if (*piVar2 != 0) {
      FUN_80054484();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  FUN_80054484();
  if (param_1 != 0) {
    FUN_8001ffa8();
  }
  if (DAT_803de338 != 0) {
    (**(code **)(*DAT_803dd724 + 0x10))();
    DAT_803de338 = 0;
  }
  return;
}

