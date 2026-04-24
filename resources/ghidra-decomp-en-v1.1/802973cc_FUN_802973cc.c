// Function: FUN_802973cc
// Entry: 802973cc
// Size: 24 bytes

void FUN_802973cc(int param_1,uint param_2)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) =
       (byte)((param_2 & 0xff) << 1) & 2 | *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) & 0xfd;
  return;
}

