// Function: FUN_80028608
// Entry: 80028608
// Size: 20 bytes

void FUN_80028608(int param_1)

{
  *(ushort *)(param_1 + 0x18) = *(ushort *)(param_1 + 0x18) ^ 2;
  return;
}

