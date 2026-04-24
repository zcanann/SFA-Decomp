// Function: FUN_80035e48
// Entry: 80035e48
// Size: 20 bytes

void FUN_80035e48(int param_1,byte param_2)

{
  *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) = *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) | param_2;
  return;
}

