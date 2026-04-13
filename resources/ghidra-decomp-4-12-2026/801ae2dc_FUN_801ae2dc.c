// Function: FUN_801ae2dc
// Entry: 801ae2dc
// Size: 136 bytes

void FUN_801ae2dc(undefined2 *param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x38))(), iVar1 == 2)) {
    FUN_801add98(param_1,(undefined2 *)*piVar2,0,0,0,0,'\0',0,0);
  }
  return;
}

