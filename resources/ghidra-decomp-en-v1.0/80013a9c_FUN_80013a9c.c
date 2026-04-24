// Function: FUN_80013a9c
// Entry: 80013a9c
// Size: 132 bytes

void FUN_80013a9c(short *param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = *(int *)(param_1 + 2);
  iVar3 = iVar2;
  iVar4 = iVar2;
  if (iVar2 == param_2) {
    *(undefined4 *)(param_1 + 2) = *(undefined4 *)(iVar2 + param_1[1]);
    *param_1 = *param_1 + -1;
    return;
  }
  for (; (iVar4 != 0 && (iVar4 != param_2)); iVar4 = *(int *)(iVar4 + param_1[1])) {
    iVar3 = iVar4;
  }
  if (iVar4 != 0) {
    uVar1 = *(undefined4 *)(iVar4 + param_1[1]);
    if (iVar4 == iVar2) {
      *(undefined4 *)(param_1 + 2) = uVar1;
    }
    else {
      *(undefined4 *)(iVar3 + param_1[1]) = uVar1;
    }
    *param_1 = *param_1 + -1;
    return;
  }
  return;
}

