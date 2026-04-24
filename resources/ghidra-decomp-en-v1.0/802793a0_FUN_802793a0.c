// Function: FUN_802793a0
// Entry: 802793a0
// Size: 252 bytes

int * FUN_802793a0(int param_1,int param_2)

{
  bool bVar1;
  int **ppiVar2;
  int **ppiVar3;
  int *piVar4;
  int *piVar5;
  int **ppiVar6;
  int **ppiVar7;
  
  ppiVar2 = DAT_803de2f8;
  piVar5 = DAT_803de2f0;
  do {
    DAT_803de2f0 = piVar5;
    piVar5 = (int *)((int)DAT_803de2f0 + 1);
  } while (DAT_803de2f0 == (int *)0xffffffff);
  piVar5 = DAT_803de2f0;
  ppiVar3 = DAT_803de2f4;
  ppiVar7 = (int **)0x0;
  DAT_803de2f0 = (int *)((int)DAT_803de2f0 + 1);
  while ((ppiVar6 = ppiVar3, ppiVar6 != (int **)0x0 && (ppiVar6[2] <= piVar5))) {
    if (ppiVar6[2] == piVar5) {
      do {
        piVar4 = (int *)((int)DAT_803de2f0 + 1);
        bVar1 = DAT_803de2f0 == (int *)0xffffffff;
        piVar5 = DAT_803de2f0;
        DAT_803de2f0 = piVar4;
      } while (bVar1);
    }
    ppiVar7 = ppiVar6;
    ppiVar3 = (int **)*ppiVar6;
  }
  if (DAT_803de2f8 != (int **)0x0) {
    DAT_803de2f8 = (int **)*DAT_803de2f8;
    if (DAT_803de2f8 != (int **)0x0) {
      *(undefined4 *)((int)DAT_803de2f8 + 4) = 0;
    }
    if (ppiVar7 == (int **)0x0) {
      DAT_803de2f4 = ppiVar2;
    }
    else {
      *ppiVar7 = (int *)ppiVar2;
    }
    ppiVar2[1] = (int *)ppiVar7;
    *ppiVar2 = (int *)ppiVar6;
    if (ppiVar6 != (int **)0x0) {
      ppiVar6[1] = (int *)ppiVar2;
    }
    ppiVar2[2] = piVar5;
    ppiVar2[3] = *(int **)(param_1 + 0xf4);
    ppiVar3 = ppiVar2;
    if (param_2 == 0) {
      ppiVar3 = (int **)0x0;
    }
    *(int ***)(param_1 + 0xfc) = ppiVar3;
    *(int ***)(param_1 + 0xf8) = ppiVar2;
    if (param_2 == 0) {
      return *(int **)(param_1 + 0xf4);
    }
    return piVar5;
  }
  return (int *)0xffffffff;
}

