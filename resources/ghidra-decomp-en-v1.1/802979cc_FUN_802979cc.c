// Function: FUN_802979cc
// Entry: 802979cc
// Size: 24 bytes

void FUN_802979cc(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) & 0xbf | 0x40;
  return;
}

