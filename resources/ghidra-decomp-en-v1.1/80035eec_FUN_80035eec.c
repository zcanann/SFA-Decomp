// Function: FUN_80035eec
// Entry: 80035eec
// Size: 60 bytes

void FUN_80035eec(int param_1,undefined param_2,undefined param_3,int param_4)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x54);
  if (iVar2 == 0) {
    return;
  }
  *(undefined *)(iVar2 + 0x6e) = param_2;
  *(undefined *)(iVar2 + 0x6f) = param_3;
  if (param_4 == -1) {
    return;
  }
  iVar1 = 1 << param_4 + 4;
  *(int *)(iVar2 + 0x48) = iVar1;
  *(int *)(iVar2 + 0x4c) = iVar1;
  return;
}

