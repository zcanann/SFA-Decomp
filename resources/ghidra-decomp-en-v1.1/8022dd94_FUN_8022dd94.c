// Function: FUN_8022dd94
// Entry: 8022dd94
// Size: 32 bytes

void FUN_8022dd94(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(byte *)(iVar1 + 0x44d) <= *(byte *)(iVar1 + 0x44c)) {
    return;
  }
  *(byte *)(iVar1 + 0x44c) = *(byte *)(iVar1 + 0x44c) + 1;
  return;
}

