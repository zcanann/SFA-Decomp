// Function: FUN_800284a4
// Entry: 800284a4
// Size: 32 bytes

int FUN_800284a4(int param_1,int param_2)

{
  return *(int *)(param_1 + (*(ushort *)(param_1 + 0x18) >> 1 & 1) * 4 + 0x1c) + param_2 * 6;
}

