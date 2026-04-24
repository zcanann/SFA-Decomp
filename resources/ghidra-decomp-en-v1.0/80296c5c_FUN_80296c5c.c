// Function: FUN_80296c5c
// Entry: 80296c5c
// Size: 16 bytes

byte FUN_80296c5c(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 2 & 1;
}

