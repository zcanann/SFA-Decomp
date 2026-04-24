// Function: FUN_800a4bb0
// Entry: 800a4bb0
// Size: 136 bytes

void FUN_800a4bb0(void)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = 0;
  piVar2 = &DAT_8039c2c0;
  do {
    if (*piVar2 != 0) {
      FUN_80023800();
    }
    *piVar2 = 0;
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 7);
  if (DAT_803dd2a4 != 0) {
    FUN_80054308();
  }
  if (DAT_803dd2a8 != 0) {
    FUN_80054308();
  }
  return;
}

