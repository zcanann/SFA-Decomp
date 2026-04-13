// Function: FUN_8018a1b0
// Entry: 8018a1b0
// Size: 16 bytes

byte FUN_8018a1b0(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x1d) >> 5 & 1;
}

