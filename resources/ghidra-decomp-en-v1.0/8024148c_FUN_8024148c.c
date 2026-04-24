// Function: FUN_8024148c
// Entry: 8024148c
// Size: 252 bytes

int * FUN_8024148c(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int **ppiVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  
  iVar5 = DAT_803dde10 + param_1 * 0xc;
  uVar1 = param_2 + 0x3fU & 0xffffffe0;
  for (piVar6 = *(int **)(iVar5 + 4); (piVar6 != (int *)0x0 && (piVar6[2] < (int)uVar1));
      piVar6 = (int *)piVar6[1]) {
  }
  if (piVar6 == (int *)0x0) {
    return (int *)0x0;
  }
  iVar2 = piVar6[2];
  if (iVar2 - uVar1 < 0x40) {
    iVar2 = *(int *)(iVar5 + 4);
    if ((int *)piVar6[1] != (int *)0x0) {
      *(int *)piVar6[1] = *piVar6;
    }
    if (*piVar6 == 0) {
      iVar2 = piVar6[1];
    }
    else {
      *(int *)(*piVar6 + 4) = piVar6[1];
    }
    *(int *)(iVar5 + 4) = iVar2;
  }
  else {
    piVar6[2] = uVar1;
    piVar4 = (int *)((int)piVar6 + uVar1);
    piVar4[2] = iVar2 - uVar1;
    *piVar4 = *piVar6;
    piVar4[1] = piVar6[1];
    if ((int **)piVar4[1] != (int **)0x0) {
      *(int **)piVar4[1] = piVar4;
    }
    if (*piVar4 == 0) {
      *(int **)(iVar5 + 4) = piVar4;
    }
    else {
      *(int **)(*piVar4 + 4) = piVar4;
    }
  }
  ppiVar3 = *(int ***)(iVar5 + 8);
  piVar6[1] = (int)ppiVar3;
  *piVar6 = 0;
  if (ppiVar3 != (int **)0x0) {
    *ppiVar3 = piVar6;
  }
  *(int **)(iVar5 + 8) = piVar6;
  return piVar6 + 8;
}

