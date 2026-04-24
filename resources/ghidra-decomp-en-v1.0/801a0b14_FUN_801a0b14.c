// Function: FUN_801a0b14
// Entry: 801a0b14
// Size: 16 bytes

byte FUN_801a0b14(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x4a) >> 5 & 1;
}

