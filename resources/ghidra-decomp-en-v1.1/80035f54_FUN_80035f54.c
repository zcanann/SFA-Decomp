// Function: FUN_80035f54
// Entry: 80035f54
// Size: 24 bytes

void FUN_80035f54(int param_1,ushort param_2)

{
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & ~param_2;
  return;
}

