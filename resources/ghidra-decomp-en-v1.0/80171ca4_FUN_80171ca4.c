// Function: FUN_80171ca4
// Entry: 80171ca4
// Size: 108 bytes

void FUN_80171ca4(int param_1,int param_2)

{
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0xe000;
  FUN_80037200(param_1,0x40);
  if (*(int *)(param_1 + 0x54) != 0) {
    FUN_80035974(param_1,(short)((int)(uint)*(ushort *)(param_2 + 0x18) >> 3));
  }
  return;
}

