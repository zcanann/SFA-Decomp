// Function: FUN_80093a24
// Entry: 80093a24
// Size: 176 bytes

void FUN_80093a24(void)

{
  int iVar1;
  int *piVar2;
  
  if (DAT_803dd1c8 != 0) {
    FUN_80054308();
    DAT_803dd1c8 = 0;
  }
  iVar1 = 0;
  piVar2 = &DAT_8039a818;
  do {
    if (*piVar2 != 0) {
      FUN_80054308();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  if (DAT_803dd1c4 != 0) {
    FUN_80054308();
    DAT_803dd1c4 = 0;
  }
  if (DAT_803dd1a0 != 0) {
    FUN_8001f384();
  }
  DAT_803dd1c0 = 0;
  return;
}

