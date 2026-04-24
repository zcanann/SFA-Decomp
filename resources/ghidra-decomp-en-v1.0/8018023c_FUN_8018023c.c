// Function: FUN_8018023c
// Entry: 8018023c
// Size: 216 bytes

void FUN_8018023c(int param_1)

{
  int iVar1;
  char cVar2;
  
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((((*(short *)(*(int *)(param_1 + 0x4c) + 0x1a) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0))
      && (iVar1 = FUN_8002b9ac(), iVar1 != 0)) &&
     (cVar2 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x44))(), cVar2 == '\0')) {
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))(iVar1,param_1,1,3);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80041018(param_1);
  }
  return;
}

