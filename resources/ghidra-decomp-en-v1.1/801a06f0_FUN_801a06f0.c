// Function: FUN_801a06f0
// Entry: 801a06f0
// Size: 16 bytes

byte FUN_801a06f0(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 8) >> 7;
}

