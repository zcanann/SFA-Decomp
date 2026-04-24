// Function: FUN_80023ed4
// Entry: 80023ed4
// Size: 200 bytes

int * FUN_80023ed4(int *param_1,int param_2,int param_3)

{
  int iVar1;
  int **ppiVar2;
  int *piVar3;
  uint uVar4;
  int **ppiVar5;
  int *piVar6;
  
  uVar4 = (uint)DAT_803dcb42;
  DAT_803dcb42 = DAT_803dcb42 + 1;
  (&DAT_803406a0)[uVar4 * 5] = param_3;
  piVar6 = &DAT_803406a4 + uVar4 * 5;
  *piVar6 = 0;
  ppiVar5 = (int **)(&DAT_803406a8 + uVar4 * 5);
  *ppiVar5 = param_1;
  (&DAT_803406ac)[uVar4 * 5] = param_2;
  *(undefined4 *)(&DAT_803406b0 + uVar4 * 0x14) = 0;
  piVar3 = *ppiVar5;
  for (iVar1 = 0; iVar1 < (int)(&DAT_803406a0)[uVar4 * 5]; iVar1 = iVar1 + 1) {
    *(short *)((int)piVar3 + 0xe) = (short)iVar1;
    piVar3 = piVar3 + 7;
  }
  ppiVar2 = (int **)*ppiVar5;
  param_1 = param_1 + param_3 * 7;
  if (((uint)param_1 & 0x1f) == 0) {
    *ppiVar2 = param_1;
  }
  else {
    *ppiVar2 = (int *)(((uint)param_1 & 0xffffffe0) + 0x20);
  }
  ppiVar2[1] = (int *)(param_2 + param_3 * -0x1c);
  *(undefined2 *)(ppiVar2 + 2) = 0;
  *(undefined2 *)((int)ppiVar2 + 10) = 0xffff;
  *(undefined2 *)(ppiVar2 + 3) = 0xffff;
  *piVar6 = *piVar6 + 1;
  return *ppiVar5;
}

