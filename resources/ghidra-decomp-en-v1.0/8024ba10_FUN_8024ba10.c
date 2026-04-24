// Function: FUN_8024ba10
// Entry: 8024ba10
// Size: 160 bytes

int ** FUN_8024ba10(void)

{
  undefined4 *puVar1;
  int **ppiVar2;
  int iVar3;
  int **ppiVar4;
  int iVar5;
  
  FUN_8024377c();
  iVar5 = 4;
  puVar1 = &DAT_803adfd8;
  iVar3 = 0;
  do {
    if ((undefined4 *)*puVar1 != puVar1) {
      FUN_802437a4();
      FUN_8024377c();
      ppiVar2 = (int **)(&DAT_803adfd8 + iVar3 * 2);
      ppiVar4 = (int **)*ppiVar2;
      *ppiVar2 = *ppiVar4;
      (*ppiVar4)[1] = (int)ppiVar2;
      FUN_802437a4();
      *ppiVar4 = (int *)0x0;
      ppiVar4[1] = (int *)0x0;
      return ppiVar4;
    }
    puVar1 = puVar1 + 2;
    iVar3 = iVar3 + 1;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  FUN_802437a4();
  return (int **)0x0;
}

