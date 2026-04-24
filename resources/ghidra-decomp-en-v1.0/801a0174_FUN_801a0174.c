// Function: FUN_801a0174
// Entry: 801a0174
// Size: 16 bytes

byte FUN_801a0174(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 8) >> 7;
}

