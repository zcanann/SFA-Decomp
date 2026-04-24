// Function: FUN_80036074
// Entry: 80036074
// Size: 16 bytes

ushort FUN_80036074(int param_1)

{
  return *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 1;
}

