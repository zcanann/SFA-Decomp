// Function: FUN_80080090
// Entry: 80080090
// Size: 112 bytes

int FUN_80080090(int *param_1,int *param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = *param_2;
  iVar2 = 0;
  piVar3 = param_1;
  iVar5 = iVar4;
  if (0 < iVar4) {
    do {
      iVar1 = *piVar3;
      piVar3 = piVar3 + 1;
      if (iVar1 == param_3) goto LAB_800800c8;
      iVar2 = iVar2 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  iVar2 = -1;
LAB_800800c8:
  if (iVar2 != -1) {
    param_1[iVar2] = param_1[iVar4 + -1];
    *param_2 = *param_2 + -1;
    return iVar2;
  }
  return -1;
}

