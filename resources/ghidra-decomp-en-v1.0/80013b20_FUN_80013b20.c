// Function: FUN_80013b20
// Entry: 80013b20
// Size: 76 bytes

void FUN_80013b20(short *param_1,int param_2,int param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 2);
  if (iVar1 == 0) {
    *(int *)(param_1 + 2) = param_3;
  }
  else {
    if (param_2 == 0) {
      *(int *)(param_1 + 2) = param_3;
    }
    else {
      iVar1 = *(int *)(param_2 + param_1[1]);
      *(int *)(param_2 + param_1[1]) = param_3;
    }
    *(int *)(param_3 + param_1[1]) = iVar1;
  }
  *param_1 = *param_1 + 1;
  return;
}

