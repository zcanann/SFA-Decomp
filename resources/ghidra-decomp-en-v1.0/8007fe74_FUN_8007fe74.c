// Function: FUN_8007fe74
// Entry: 8007fe74
// Size: 56 bytes

int FUN_8007fe74(int *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  if (0 < param_2) {
    do {
      iVar1 = *param_1;
      param_1 = param_1 + 1;
      if (iVar1 == param_3) {
        return iVar2;
      }
      iVar2 = iVar2 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return -1;
}

