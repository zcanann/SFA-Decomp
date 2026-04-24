// Function: FUN_80028558
// Entry: 80028558
// Size: 20 bytes

void FUN_80028558(int param_1)

{
  *(ushort *)(param_1 + 0x18) = *(ushort *)(param_1 + 0x18) ^ 1;
  return;
}

