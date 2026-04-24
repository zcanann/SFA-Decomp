// Function: FUN_801a0bdc
// Entry: 801a0bdc
// Size: 56 bytes

void FUN_801a0bdc(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0x4a) = *(byte *)(iVar1 + 0x4a) & 0xdf | 0x20;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) & 0xfd;
  return;
}

