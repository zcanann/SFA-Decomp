// Function: FUN_80172150
// Entry: 80172150
// Size: 108 bytes

void FUN_80172150(int param_1,int param_2)

{
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0xe000;
  FUN_800372f8(param_1,0x40);
  if (*(int *)(param_1 + 0x54) != 0) {
    FUN_80035a6c(param_1,(short)((int)(uint)*(ushort *)(param_2 + 0x18) >> 3));
  }
  return;
}

