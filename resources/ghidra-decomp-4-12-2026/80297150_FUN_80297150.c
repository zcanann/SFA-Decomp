// Function: FUN_80297150
// Entry: 80297150
// Size: 36 bytes

uint FUN_80297150(int param_1)

{
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x3f1) & 1) != 0) {
    return (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x86c);
  }
  return 0xffffffff;
}

