// Function: FUN_80037ef0
// Entry: 80037ef0
// Size: 180 bytes

undefined4 FUN_80037ef0(int param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar1 = DAT_803dcbf8;
  if ((param_1 == 0) || (param_2 == 0)) {
    return 0;
  }
  piVar2 = &DAT_80342d50;
  iVar3 = DAT_803dcbf8;
  if (DAT_803dcbf8 != 0) {
    do {
      if ((*piVar2 == param_1) && (piVar2[1] == param_2)) {
        return 0;
      }
      piVar2 = piVar2 + 3;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (0xf < DAT_803dcbf8) {
    return 0;
  }
  (&DAT_80342d50)[DAT_803dcbf8 * 3] = param_1;
  (&DAT_80342d54)[iVar1 * 3] = param_2;
  (&DAT_80342d58)[iVar1 * 3] = param_3;
  *(char *)(param_1 + 0xe9) = *(char *)(param_1 + 0xe9) + '\x01';
  *(char *)(param_2 + 0xe9) = *(char *)(param_2 + 0xe9) + '\x01';
  DAT_803dcbf8 = DAT_803dcbf8 + 1;
  return 1;
}

