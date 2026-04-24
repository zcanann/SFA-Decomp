// Function: FUN_80028544
// Entry: 80028544
// Size: 20 bytes

void FUN_80028544(int param_1)

{
  *(ushort *)(param_1 + 0x18) = *(ushort *)(param_1 + 0x18) ^ 2;
  return;
}

