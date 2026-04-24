// Function: FUN_80236b38
// Entry: 80236b38
// Size: 56 bytes

void FUN_80236b38(int param_1,char param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 != '\0') {
    *(byte *)(iVar1 + 0x22) = *(byte *)(iVar1 + 0x22) | 2;
    return;
  }
  *(byte *)(iVar1 + 0x22) = *(byte *)(iVar1 + 0x22) & 0xfd;
  return;
}

