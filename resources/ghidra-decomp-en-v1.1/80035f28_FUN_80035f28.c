// Function: FUN_80035f28
// Entry: 80035f28
// Size: 24 bytes

void FUN_80035f28(int param_1,byte param_2)

{
  *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) = *(byte *)(*(int *)(param_1 + 0x54) + 0xb4) & ~param_2
  ;
  return;
}

