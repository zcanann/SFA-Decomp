// Function: FUN_80037fe8
// Entry: 80037fe8
// Size: 180 bytes

undefined4 FUN_80037fe8(int param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar1 = DAT_803dd878;
  if ((param_1 == 0) || (param_2 == 0)) {
    return 0;
  }
  piVar2 = &DAT_803439b0;
  iVar3 = DAT_803dd878;
  if (DAT_803dd878 != 0) {
    do {
      if ((*piVar2 == param_1) && (piVar2[1] == param_2)) {
        return 0;
      }
      piVar2 = piVar2 + 3;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (0xf < DAT_803dd878) {
    return 0;
  }
  (&DAT_803439b0)[DAT_803dd878 * 3] = param_1;
  (&DAT_803439b4)[iVar1 * 3] = param_2;
  (&DAT_803439b8)[iVar1 * 3] = param_3;
  *(char *)(param_1 + 0xe9) = *(char *)(param_1 + 0xe9) + '\x01';
  *(char *)(param_2 + 0xe9) = *(char *)(param_2 + 0xe9) + '\x01';
  DAT_803dd878 = DAT_803dd878 + 1;
  return 1;
}

