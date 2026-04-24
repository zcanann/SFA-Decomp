// Function: FUN_80037e44
// Entry: 80037e44
// Size: 172 bytes

void FUN_80037e44(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  piVar1 = &DAT_80342d50;
  iVar3 = DAT_803dcbf8;
  while (iVar4 = iVar3 + -1, 0 < iVar3) {
    if ((*piVar1 == param_1) || (piVar1[1] == param_1)) {
      DAT_803dcbf8 = DAT_803dcbf8 + -1;
      iVar4 = iVar3 + -2;
      *(char *)(*piVar1 + 0xe9) = *(char *)(*piVar1 + 0xe9) + -1;
      *(char *)(piVar1[1] + 0xe9) = *(char *)(piVar1[1] + 0xe9) + -1;
      iVar3 = DAT_803dcbf8;
      if ((DAT_803dcbf8 != 0xf) && (DAT_803dcbf8 != 0)) {
        iVar2 = (&DAT_80342d54)[DAT_803dcbf8 * 3];
        *piVar1 = (&DAT_80342d50)[DAT_803dcbf8 * 3];
        piVar1[1] = iVar2;
        piVar1[2] = (&DAT_80342d58)[iVar3 * 3];
      }
    }
    piVar1 = piVar1 + 3;
    iVar3 = iVar4;
  }
  return;
}

