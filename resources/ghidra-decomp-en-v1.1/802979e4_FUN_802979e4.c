// Function: FUN_802979e4
// Entry: 802979e4
// Size: 24 bytes

void FUN_802979e4(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) & 0x7f | 0x80;
  return;
}

