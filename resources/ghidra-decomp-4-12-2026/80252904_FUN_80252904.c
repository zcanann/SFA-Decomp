// Function: FUN_80252904
// Entry: 80252904
// Size: 244 bytes

undefined4 FUN_80252904(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  FUN_80243e74();
  piVar2 = &DAT_803af000;
  iVar3 = 4;
  iVar1 = 0;
  do {
    if (*piVar2 == param_1) {
      (&DAT_803af000)[iVar1] = 0;
      iVar1 = 0;
      if ((((DAT_803af000 == 0) && (iVar1 = 1, DAT_803af004 == 0)) && (iVar1 = 2, DAT_803af008 == 0)
          ) && (iVar1 = 3, DAT_803af00c == 0)) {
        iVar1 = 4;
      }
      if (iVar1 == 4) {
        FUN_802527a0(0);
      }
      FUN_80243e9c();
      return 1;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  FUN_80243e9c();
  return 0;
}

