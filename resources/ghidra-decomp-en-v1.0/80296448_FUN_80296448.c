// Function: FUN_80296448
// Entry: 80296448
// Size: 16 bytes

byte FUN_80296448(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f0) >> 5 & 1;
}

