// Function: FUN_80189c58
// Entry: 80189c58
// Size: 16 bytes

byte FUN_80189c58(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x1d) >> 5 & 1;
}

