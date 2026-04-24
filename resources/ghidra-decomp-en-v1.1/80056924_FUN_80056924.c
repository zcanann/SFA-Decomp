// Function: FUN_80056924
// Entry: 80056924
// Size: 708 bytes

int FUN_80056924(int param_1,int param_2,uint param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar4 = 0x10;
  piVar2 = DAT_803ddaec;
  do {
    if ((((*(short *)(piVar2 + 3) != 0) && (*piVar2 == param_1)) &&
        (iVar1 = iVar3, param_3 == *(byte *)((int)piVar2 + 0xe))) ||
       ((((((iVar1 = iVar3 + 1, *(short *)(piVar2 + 7) != 0 && (piVar2[4] == param_1)) &&
           (param_3 == *(byte *)((int)piVar2 + 0x1e))) ||
          (((iVar1 = iVar3 + 2, *(short *)(piVar2 + 0xb) != 0 && (piVar2[8] == param_1)) &&
           (param_3 == *(byte *)((int)piVar2 + 0x2e))))) ||
         (((iVar1 = iVar3 + 3, *(short *)(piVar2 + 0xf) != 0 && (piVar2[0xc] == param_1)) &&
          (param_3 == *(byte *)((int)piVar2 + 0x3e))))) ||
        (((*(short *)(piVar2 + 0x13) != 0 && (piVar2[0x10] == param_1)) &&
         (iVar1 = iVar3 + 4, param_3 == *(byte *)((int)piVar2 + 0x4e))))))) break;
    piVar2 = piVar2 + 0x14;
    iVar3 = iVar3 + 5;
    iVar4 = iVar4 + -1;
    iVar1 = -1;
  } while (iVar4 != 0);
  if (iVar1 == -1) {
    iVar3 = 0;
    iVar4 = 8;
    piVar2 = DAT_803ddaec;
    do {
      iVar1 = iVar3;
      if (((((*(short *)(piVar2 + 3) == 0) || (iVar1 = iVar3 + 1, *(short *)(piVar2 + 7) == 0)) ||
           ((iVar1 = iVar3 + 2, *(short *)(piVar2 + 0xb) == 0 ||
            ((((iVar1 = iVar3 + 3, *(short *)(piVar2 + 0xf) == 0 ||
               (iVar1 = iVar3 + 4, *(short *)(piVar2 + 0x13) == 0)) ||
              (iVar1 = iVar3 + 5, *(short *)(piVar2 + 0x17) == 0)) ||
             ((iVar1 = iVar3 + 6, *(short *)(piVar2 + 0x1b) == 0 ||
              (iVar1 = iVar3 + 7, *(short *)(piVar2 + 0x1f) == 0)))))))) ||
          (iVar1 = iVar3 + 8, *(short *)(piVar2 + 0x23) == 0)) ||
         (iVar1 = iVar3 + 9, *(short *)(piVar2 + 0x27) == 0)) break;
      piVar2 = piVar2 + 0x28;
      iVar3 = iVar3 + 10;
      iVar4 = iVar4 + -1;
      iVar1 = -1;
    } while (iVar4 != 0);
    if (iVar1 == -1) {
      FUN_8007d858();
      iVar1 = 0;
    }
    else {
      *(undefined2 *)(DAT_803ddaec + iVar1 * 4 + 3) = 1;
      DAT_803ddaec[iVar1 * 4 + 1] = 0;
      DAT_803ddaec[iVar1 * 4 + 2] = param_2;
      DAT_803ddaec[iVar1 * 4] = param_1;
      *(char *)((int)DAT_803ddaec + iVar1 * 0x10 + 0xe) = (char)param_3;
    }
  }
  else {
    *(short *)(DAT_803ddaec + iVar1 * 4 + 3) = *(short *)(DAT_803ddaec + iVar1 * 4 + 3) + 1;
  }
  return iVar1;
}

