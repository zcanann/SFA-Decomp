// Function: FUN_80035e30
// Entry: 80035e30
// Size: 24 bytes

void FUN_80035e30(int param_1,byte param_2)

{
  *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) = *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) & ~param_2
  ;
  return;
}

