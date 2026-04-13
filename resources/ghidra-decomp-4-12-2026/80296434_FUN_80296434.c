// Function: FUN_80296434
// Entry: 80296434
// Size: 16 bytes

byte FUN_80296434(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 3 & 1;
}

