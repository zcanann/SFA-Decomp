// Function: FUN_80296c78
// Entry: 80296c78
// Size: 60 bytes

void FUN_80296c78(int param_1,byte param_2,int param_3)

{
  int iVar1;
  
  if (param_3 != 0) {
    iVar1 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
    *(byte *)(iVar1 + 2) = *(byte *)(iVar1 + 2) | param_2;
    return;
  }
  iVar1 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
  *(byte *)(iVar1 + 2) = *(byte *)(iVar1 + 2) & ~param_2;
  return;
}

