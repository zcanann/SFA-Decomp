// Function: FUN_800a2008
// Entry: 800a2008
// Size: 208 bytes

void FUN_800a2008(int param_1)

{
  int *piVar1;
  int iVar2;
  int **ppiVar3;
  
  iVar2 = 0;
  ppiVar3 = (int **)&DAT_8039c1f8;
  do {
    piVar1 = *ppiVar3;
    if ((piVar1 != (int *)0x0) && (piVar1[1] == param_1)) {
      if (*piVar1 != 0) {
        FUN_8002cbc4();
      }
      (*ppiVar3)[0x4b] = 0;
      if ((*(char *)((int)*ppiVar3 + 0x13f) == '\0') && ((*ppiVar3)[0x26] != 0)) {
        FUN_80054308();
      }
      if (*(char *)((int)*ppiVar3 + 0x13f) == '\0') {
        (*ppiVar3)[0x26] = 0;
      }
      FUN_80023800(*ppiVar3);
      *ppiVar3 = (int *)0x0;
    }
    ppiVar3 = ppiVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x32);
  return;
}

