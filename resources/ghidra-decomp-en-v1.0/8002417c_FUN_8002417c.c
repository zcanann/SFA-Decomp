// Function: FUN_8002417c
// Entry: 8002417c
// Size: 400 bytes

int ** FUN_8002417c(int param_1,int param_2)

{
  bool bVar1;
  undefined4 uVar2;
  int **ppiVar3;
  uint uVar4;
  int **ppiVar5;
  int **ppiVar6;
  int *piVar7;
  int *piVar8;
  int iVar9;
  uint uVar10;
  
  uVar2 = FUN_80022d20(2);
  ppiVar3 = (int **)FUN_80023cc8(param_2 * param_1 + 0x20,0x11,0);
  FUN_80022d20(uVar2);
  *(short *)(ppiVar3 + 3) = (short)param_2;
  *(short *)((int)ppiVar3 + 0xe) = (short)param_1;
  *(undefined2 *)(ppiVar3 + 4) = 0;
  ppiVar3[1] = (int *)((int)ppiVar3 +
                      (int)*(short *)((int)ppiVar3 + 0xe) * (int)*(short *)(ppiVar3 + 3) + 0x20);
  ppiVar6 = ppiVar3 + 8;
  piVar7 = (int *)((int)ppiVar6 + param_2);
  uVar4 = param_1 - 2;
  ppiVar5 = ppiVar6;
  if (0 < (int)uVar4) {
    uVar10 = uVar4 >> 3;
    if (uVar10 != 0) {
      do {
        *ppiVar5 = piVar7;
        ppiVar5 = (int **)*ppiVar5;
        *ppiVar5 = (int *)((int)piVar7 + param_2);
        ppiVar5 = (int **)*ppiVar5;
        piVar8 = (int *)((int)(int *)((int)piVar7 + param_2) + param_2);
        *ppiVar5 = piVar8;
        ppiVar5 = (int **)*ppiVar5;
        piVar8 = (int *)((int)piVar8 + param_2);
        *ppiVar5 = piVar8;
        ppiVar5 = (int **)*ppiVar5;
        piVar8 = (int *)((int)piVar8 + param_2);
        *ppiVar5 = piVar8;
        ppiVar5 = (int **)*ppiVar5;
        piVar8 = (int *)((int)piVar8 + param_2);
        *ppiVar5 = piVar8;
        ppiVar5 = (int **)*ppiVar5;
        piVar8 = (int *)((int)piVar8 + param_2);
        *ppiVar5 = piVar8;
        piVar7 = *ppiVar5;
        iVar9 = (int)piVar8 + param_2;
        *piVar7 = iVar9;
        ppiVar5 = (int **)*piVar7;
        piVar7 = (int *)(iVar9 + param_2);
        uVar10 = uVar10 - 1;
      } while (uVar10 != 0);
      uVar4 = uVar4 & 7;
      if (uVar4 == 0) goto LAB_800242a4;
    }
    do {
      *ppiVar5 = piVar7;
      ppiVar5 = (int **)*ppiVar5;
      piVar7 = (int *)((int)piVar7 + param_2);
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
LAB_800242a4:
  *ppiVar5 = (int *)0x0;
  *ppiVar3 = (int *)ppiVar6;
  ppiVar5 = (int **)*ppiVar3;
  while( true ) {
    if (ppiVar5 == (int **)0x0) {
      return ppiVar3;
    }
    bVar1 = false;
    if ((ppiVar6 <= ppiVar5) && (ppiVar5 < ppiVar3[1])) {
      bVar1 = true;
    }
    if (!bVar1) break;
    ppiVar5 = (int **)*ppiVar5;
  }
  return ppiVar3;
}

