// Function: FUN_802969f0
// Entry: 802969f0
// Size: 36 bytes

uint FUN_802969f0(int param_1)

{
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x3f1) & 1) != 0) {
    return (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x86c);
  }
  return 0xffffffff;
}

