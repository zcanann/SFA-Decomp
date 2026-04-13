// Function: FUN_80136c68
// Entry: 80136c68
// Size: 124 bytes

void FUN_80136c68(void)

{
  int iVar1;
  int *piVar2;
  
  FUN_80054484();
  DAT_803de654 = 0;
  iVar1 = 0;
  piVar2 = &DAT_803aabf8;
  do {
    if (*piVar2 != 0) {
      FUN_80054484();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x13);
  DAT_803de612 = 0;
  return;
}

