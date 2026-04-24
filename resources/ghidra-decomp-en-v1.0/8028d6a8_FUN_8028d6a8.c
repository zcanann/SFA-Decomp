// Function: FUN_8028d6a8
// Entry: 8028d6a8
// Size: 508 bytes

void FUN_8028d6a8(int **param_1,int **param_2,uint param_3)

{
  uint *puVar1;
  int **ppiVar2;
  int **ppiVar3;
  int *piVar4;
  int *piVar5;
  bool bVar6;
  int iVar7;
  
  iVar7 = 0;
  for (puVar1 = &DAT_802c2a00; *puVar1 < param_3; puVar1 = puVar1 + 1) {
    iVar7 = iVar7 + 1;
  }
  ppiVar2 = (int **)param_2[-1];
  ppiVar3 = param_1 + iVar7 * 2 + 1;
  if (ppiVar2[3] == (int *)0x0) {
    if ((int **)ppiVar3[1] != ppiVar2) {
      if ((int **)*ppiVar3 == ppiVar2) {
        ppiVar3[1] = (int *)*ppiVar3[1];
        *ppiVar3 = (int *)**ppiVar3;
      }
      else {
        (*ppiVar2)[1] = (int)ppiVar2[1];
        *ppiVar2[1] = (int)*ppiVar2;
        ppiVar2[1] = ppiVar3[1];
        *ppiVar2 = (int *)*ppiVar2[1];
        (*ppiVar2)[1] = (int)ppiVar2;
        *ppiVar2[1] = (int)ppiVar2;
        ppiVar3[1] = (int *)ppiVar2;
      }
    }
  }
  *param_2 = ppiVar2[3];
  ppiVar2[3] = (int *)(param_2 + -1);
  piVar5 = ppiVar2[4];
  ppiVar2[4] = (int *)((int)piVar5 + -1);
  if ((int *)((int)piVar5 + -1) == (int *)0x0) {
    if ((int **)ppiVar3[1] == ppiVar2) {
      ppiVar3[1] = ppiVar2[1];
    }
    if ((int **)*ppiVar3 == ppiVar2) {
      *ppiVar3 = *ppiVar2;
    }
    (*ppiVar2)[1] = (int)ppiVar2[1];
    *ppiVar2[1] = (int)*ppiVar2;
    if ((int **)ppiVar3[1] == ppiVar2) {
      ppiVar3[1] = (int *)0x0;
    }
    if ((int **)*ppiVar3 == ppiVar2) {
      *ppiVar3 = (int *)0x0;
    }
    piVar5 = (int *)((uint)ppiVar2[-1] & 0xfffffffe);
    FUN_8028d960(piVar5,ppiVar2 + -2);
    bVar6 = false;
    if (((piVar5[4] & 2U) == 0) && ((piVar5[4] & 0xfffffff8U) == (piVar5[3] & 0xfffffff8U) - 0x18))
    {
      bVar6 = true;
    }
    if (bVar6) {
      piVar4 = (int *)piVar5[1];
      if (piVar4 == piVar5) {
        piVar4 = (int *)0x0;
      }
      if (*param_1 == piVar5) {
        *param_1 = piVar4;
      }
      if (piVar4 != (int *)0x0) {
        *piVar4 = *piVar5;
        *(int **)(*piVar4 + 4) = piVar4;
      }
      piVar5[1] = 0;
      *piVar5 = 0;
      FUN_802867bc(piVar5);
    }
  }
  return;
}

