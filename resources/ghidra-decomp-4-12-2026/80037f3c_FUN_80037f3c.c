// Function: FUN_80037f3c
// Entry: 80037f3c
// Size: 172 bytes

void FUN_80037f3c(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  piVar1 = &DAT_803439b0;
  iVar3 = DAT_803dd878;
  while (iVar4 = iVar3 + -1, 0 < iVar3) {
    if ((*piVar1 == param_1) || (piVar1[1] == param_1)) {
      DAT_803dd878 = DAT_803dd878 + -1;
      iVar4 = iVar3 + -2;
      *(char *)(*piVar1 + 0xe9) = *(char *)(*piVar1 + 0xe9) + -1;
      *(char *)(piVar1[1] + 0xe9) = *(char *)(piVar1[1] + 0xe9) + -1;
      iVar3 = DAT_803dd878;
      if ((DAT_803dd878 != 0xf) && (DAT_803dd878 != 0)) {
        iVar2 = (&DAT_803439b4)[DAT_803dd878 * 3];
        *piVar1 = (&DAT_803439b0)[DAT_803dd878 * 3];
        piVar1[1] = iVar2;
        piVar1[2] = (&DAT_803439b8)[iVar3 * 3];
      }
    }
    piVar1 = piVar1 + 3;
    iVar3 = iVar4;
  }
  return;
}

