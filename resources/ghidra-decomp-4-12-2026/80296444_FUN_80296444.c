// Function: FUN_80296444
// Entry: 80296444
// Size: 16 bytes

byte FUN_80296444(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f4) >> 6 & 1;
}

