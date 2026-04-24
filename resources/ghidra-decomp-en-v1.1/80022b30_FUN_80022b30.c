// Function: FUN_80022b30
// Entry: 80022b30
// Size: 228 bytes

int FUN_80022b30(int param_1,int param_2)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = (int *)0x0;
  iVar3 = 0;
  piVar1 = &DAT_8033d400;
  do {
    if (0x1f < iVar3) {
LAB_80022bb0:
      if (piVar2 == (int *)0x0) {
        return 0;
      }
      if (piVar2[2] - (piVar2[1] - *piVar2) < param_2) {
        FUN_8007d858();
        return 0;
      }
      piVar2[1] = piVar2[1] + param_2;
      return piVar2[1] - param_2;
    }
    if ((*piVar1 != 0) && (param_1 == *(int *)(*piVar1 + 0xc))) {
      piVar2 = (int *)(&DAT_8033d400)[iVar3];
      goto LAB_80022bb0;
    }
    piVar1 = piVar1 + 1;
    iVar3 = iVar3 + 1;
    if (iVar3 == 0x20) {
      FUN_8007d858();
      return 0;
    }
  } while( true );
}

