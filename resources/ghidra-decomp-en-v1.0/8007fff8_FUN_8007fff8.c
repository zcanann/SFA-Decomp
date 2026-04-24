// Function: FUN_8007fff8
// Entry: 8007fff8
// Size: 128 bytes

int FUN_8007fff8(int *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (0x10 < param_2) {
    iVar1 = 0;
    while( true ) {
      iVar3 = param_2 + iVar1 >> 1;
      iVar2 = iVar3;
      if ((param_3 <= param_1[iVar3 * 2]) &&
         (param_2 = iVar3, iVar2 = iVar1, param_3 == param_1[iVar3 * 2])) break;
      iVar1 = iVar2;
      if (iVar2 < param_2) {
        return 0;
      }
    }
    return param_1[iVar3 * 2 + 1];
  }
  if (param_2 != 0) {
    do {
      if (*param_1 == param_3) {
        return param_1[1];
      }
      param_1 = param_1 + 2;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return 0;
}

