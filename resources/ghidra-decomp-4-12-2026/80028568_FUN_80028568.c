// Function: FUN_80028568
// Entry: 80028568
// Size: 32 bytes

int FUN_80028568(int param_1,int param_2)

{
  return *(int *)(param_1 + (*(ushort *)(param_1 + 0x18) >> 1 & 1) * 4 + 0x1c) + param_2 * 6;
}

