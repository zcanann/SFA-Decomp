// Function: FUN_8022f0ec
// Entry: 8022f0ec
// Size: 84 bytes

void FUN_8022f0ec(short *param_1,int param_2)

{
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  FUN_80037200(param_1,0x52);
  return;
}

