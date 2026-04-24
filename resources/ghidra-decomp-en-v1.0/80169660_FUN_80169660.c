// Function: FUN_80169660
// Entry: 80169660
// Size: 108 bytes

void FUN_80169660(short *param_1,int param_2)

{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  FUN_80030334((double)FLOAT_803e30d4,param_1,0,0);
  return;
}

