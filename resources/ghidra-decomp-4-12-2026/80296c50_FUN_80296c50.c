// Function: FUN_80296c50
// Entry: 80296c50
// Size: 40 bytes

uint FUN_80296c50(int param_1,uint param_2)

{
  if (0xb < param_2) {
    return 0;
  }
  return (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x8c7) & 1 << param_2;
}

