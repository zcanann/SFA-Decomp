// Function: FUN_801add28
// Entry: 801add28
// Size: 136 bytes

void FUN_801add28(int param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x38))(), iVar1 == 2)) {
    FUN_801ad7e4(param_1,*piVar2,0,0,0,0,0,0,0);
  }
  return;
}

