// Function: FUN_8018c038
// Entry: 8018c038
// Size: 68 bytes

void FUN_8018c038(short *param_1,int param_2)

{
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  FUN_8002b738((int)param_1,(ushort)*(byte *)(param_2 + 0x19));
  return;
}

