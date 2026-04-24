// Function: FUN_8022f7b0
// Entry: 8022f7b0
// Size: 84 bytes

void FUN_8022f7b0(short *param_1,int param_2)

{
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  FUN_800372f8((int)param_1,0x52);
  return;
}

