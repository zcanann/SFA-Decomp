// Function: FUN_801a1090
// Entry: 801a1090
// Size: 16 bytes

byte FUN_801a1090(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x4a) >> 5 & 1;
}

