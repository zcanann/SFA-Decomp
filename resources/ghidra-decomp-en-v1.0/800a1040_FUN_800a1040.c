// Function: FUN_800a1040
// Entry: 800a1040
// Size: 252 bytes

void FUN_800a1040(short param_1,int param_2)

{
  int *piVar1;
  int **ppiVar2;
  int iVar3;
  
  iVar3 = 0;
  ppiVar2 = (int **)&DAT_8039c1f8;
  do {
    piVar1 = *ppiVar2;
    if ((piVar1 != (int *)0x0) && ((param_1 == *(short *)(piVar1 + 0x43) || (param_2 != 0)))) {
      if (piVar1[0x28] != 0) {
        FUN_80023800();
      }
      if (**ppiVar2 != 0) {
        FUN_8002cbc4();
      }
      (*ppiVar2)[0x4b] = 0;
      if ((*(char *)((int)*ppiVar2 + 0x13f) == '\0') && ((*ppiVar2)[0x26] != 0)) {
        FUN_80054308();
      }
      if (*(char *)((int)*ppiVar2 + 0x13f) == '\0') {
        (*ppiVar2)[0x26] = 0;
      }
      FUN_80023800(*ppiVar2);
      *ppiVar2 = (int *)0x0;
    }
    ppiVar2 = ppiVar2 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x32);
  return;
}

