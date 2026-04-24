// Function: FUN_8001b700
// Entry: 8001b700
// Size: 184 bytes

void FUN_8001b700(void)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  
  if (DAT_803dca04 != 0) {
    DAT_803dca04 = 0;
    piVar3 = &DAT_8033b240;
    for (iVar2 = 0; iVar2 < DAT_803dca14; iVar2 = iVar2 + 1) {
      if (*piVar3 != 0) {
        uVar1 = FUN_80023834(0);
        FUN_80023800(*piVar3);
        FUN_80023834(uVar1);
        *piVar3 = 0;
      }
      piVar3 = piVar3 + 1;
    }
    if (DAT_803db3e0 != -1) {
      FUN_80019970();
      DAT_803db3e0 = -1;
    }
  }
  return;
}

