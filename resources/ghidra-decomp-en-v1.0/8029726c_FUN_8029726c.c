// Function: FUN_8029726c
// Entry: 8029726c
// Size: 24 bytes

void FUN_8029726c(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) & 0xbf | 0x40;
  return;
}

