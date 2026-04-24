// Function: FUN_802385ec
// Entry: 802385ec
// Size: 24 bytes

void FUN_802385ec(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0xd) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0xd) & 0xbf | 0x40;
  return;
}

