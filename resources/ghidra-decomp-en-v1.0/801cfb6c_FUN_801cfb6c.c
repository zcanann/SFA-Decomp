// Function: FUN_801cfb6c
// Entry: 801cfb6c
// Size: 64 bytes

void FUN_801cfb6c(int param_1)

{
  *(undefined **)(param_1 + 0xbc) = &LAB_801cfb24;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  FUN_80037200(param_1,0x3d);
  return;
}

