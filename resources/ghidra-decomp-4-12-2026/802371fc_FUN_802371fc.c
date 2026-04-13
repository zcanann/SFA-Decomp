// Function: FUN_802371fc
// Entry: 802371fc
// Size: 56 bytes

void FUN_802371fc(int param_1,char param_2)

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

