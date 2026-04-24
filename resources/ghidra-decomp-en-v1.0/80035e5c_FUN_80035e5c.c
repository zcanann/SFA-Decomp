// Function: FUN_80035e5c
// Entry: 80035e5c
// Size: 24 bytes

void FUN_80035e5c(int param_1,ushort param_2)

{
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~param_2;
  return;
}

