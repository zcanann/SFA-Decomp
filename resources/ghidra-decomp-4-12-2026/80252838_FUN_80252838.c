// Function: FUN_80252838
// Entry: 80252838
// Size: 204 bytes

undefined4 FUN_80252838(int param_1)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  FUN_80243e74();
  piVar2 = &DAT_803af000;
  iVar3 = 4;
  piVar1 = piVar2;
  do {
    if (*piVar1 == param_1) {
      FUN_80243e9c();
      return 1;
    }
    piVar1 = piVar1 + 1;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  iVar4 = 4;
  iVar3 = 0;
  do {
    if (*piVar2 == 0) {
      (&DAT_803af000)[iVar3] = param_1;
      FUN_802527a0(1);
      FUN_80243e9c();
      return 1;
    }
    piVar2 = piVar2 + 1;
    iVar3 = iVar3 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  FUN_80243e9c();
  return 0;
}

