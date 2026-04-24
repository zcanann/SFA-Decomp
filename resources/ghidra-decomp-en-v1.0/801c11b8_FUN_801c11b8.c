// Function: FUN_801c11b8
// Entry: 801c11b8
// Size: 128 bytes

void FUN_801c11b8(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar4 = 0;
  for (iVar1 = param_2; iVar2 = param_3, *(int *)(iVar1 + 0x28) != 0; iVar1 = iVar1 + 4) {
    iVar3 = iVar3 + 1;
  }
  for (; *(int *)(iVar2 + 0x28) != 0; iVar2 = iVar2 + 4) {
    iVar4 = iVar4 + 1;
  }
  if (iVar3 <= (int)(uint)*(byte *)(param_2 + 0x24)) {
    if (iVar4 <= (int)(uint)*(byte *)(param_3 + 0x24)) {
      *(int *)(param_2 + iVar3 * 4 + 0x28) = param_1;
      *(int *)(param_3 + iVar4 * 4 + 0x28) = param_1;
      *(int *)(param_1 + 4) = param_2;
      *(int *)(param_1 + 8) = param_3;
      return;
    }
    return;
  }
  return;
}

