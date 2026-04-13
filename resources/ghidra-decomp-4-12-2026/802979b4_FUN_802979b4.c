// Function: FUN_802979b4
// Entry: 802979b4
// Size: 24 bytes

void FUN_802979b4(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) & 0xdf | 0x20;
  return;
}

