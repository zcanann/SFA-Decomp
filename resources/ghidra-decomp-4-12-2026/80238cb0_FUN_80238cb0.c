// Function: FUN_80238cb0
// Entry: 80238cb0
// Size: 24 bytes

void FUN_80238cb0(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0xd) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0xd) & 0xbf | 0x40;
  return;
}

