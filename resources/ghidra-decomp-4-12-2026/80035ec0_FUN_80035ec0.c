// Function: FUN_80035ec0
// Entry: 80035ec0
// Size: 44 bytes

void FUN_80035ec0(int param_1,undefined param_2,undefined param_3,int param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  *(undefined *)(iVar1 + 0x6e) = param_2;
  *(undefined *)(iVar1 + 0x6f) = param_3;
  if (param_4 == 0) {
    return;
  }
  *(int *)(iVar1 + 0x48) = param_4 << 4;
  *(int *)(iVar1 + 0x4c) = param_4 << 4;
  return;
}

