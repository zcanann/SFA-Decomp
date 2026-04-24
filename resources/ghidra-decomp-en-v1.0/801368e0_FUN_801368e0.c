// Function: FUN_801368e0
// Entry: 801368e0
// Size: 124 bytes

void FUN_801368e0(void)

{
  int iVar1;
  int *piVar2;
  
  FUN_80054308(DAT_803dd9d4);
  DAT_803dd9d4 = 0;
  iVar1 = 0;
  piVar2 = &DAT_803a9f98;
  do {
    if (*piVar2 != 0) {
      FUN_80054308();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x13);
  DAT_803dd992 = 0;
  return;
}

