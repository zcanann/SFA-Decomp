// Function: FUN_80035f7c
// Entry: 80035f7c
// Size: 16 bytes

ushort FUN_80035f7c(int param_1)

{
  return *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 1;
}

