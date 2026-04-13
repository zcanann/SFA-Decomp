// Function: FUN_801d013c
// Entry: 801d013c
// Size: 64 bytes

void FUN_801d013c(int param_1)

{
  *(undefined **)(param_1 + 0xbc) = &LAB_801d00f4;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  FUN_800372f8(param_1,0x3d);
  return;
}

