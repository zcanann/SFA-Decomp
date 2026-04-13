// Function: FUN_8028364c
// Entry: 8028364c
// Size: 152 bytes

int FUN_8028364c(undefined4 param_1,int param_2,int param_3,int param_4,undefined *param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  if (param_3 != 0) {
    iVar4 = 1;
    do {
      iVar3 = iVar4 + param_3 >> 1;
      iVar5 = iVar3 + -1;
      iVar2 = param_2 + param_4 * iVar5;
      iVar1 = (*(code *)param_5)(param_1,iVar2);
      if (iVar1 == 0) {
        return iVar2;
      }
      if (-1 < iVar1) {
        iVar4 = iVar3 + 1;
        iVar5 = param_3;
      }
      param_3 = iVar5;
    } while (iVar4 <= iVar5);
  }
  return 0;
}

