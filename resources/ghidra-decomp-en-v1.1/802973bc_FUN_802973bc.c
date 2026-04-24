// Function: FUN_802973bc
// Entry: 802973bc
// Size: 16 bytes

byte FUN_802973bc(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 2 & 1;
}

