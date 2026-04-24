// Function: FUN_80296c4c
// Entry: 80296c4c
// Size: 16 bytes

byte FUN_80296c4c(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 1 & 1;
}

