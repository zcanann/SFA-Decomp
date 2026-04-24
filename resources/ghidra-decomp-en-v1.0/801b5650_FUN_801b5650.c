// Function: FUN_801b5650
// Entry: 801b5650
// Size: 104 bytes

void FUN_801b5650(void)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = 0;
  piVar2 = &DAT_803ac960;
  do {
    if (*piVar2 != 0) {
      FUN_80054308();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  return;
}

