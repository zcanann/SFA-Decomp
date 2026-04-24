// Function: FUN_801a86a4
// Entry: 801a86a4
// Size: 88 bytes

void FUN_801a86a4(int param_1,char param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 != '\0') {
    *(ushort *)(iVar1 + 0x24) = *(ushort *)(iVar1 + 0x24) | 4;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    return;
  }
  *(ushort *)(iVar1 + 0x24) = *(ushort *)(iVar1 + 0x24) & 0xfffb;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  return;
}

