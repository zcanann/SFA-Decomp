// Function: FUN_8018babc
// Entry: 8018babc
// Size: 68 bytes

void FUN_8018babc(short *param_1,int param_2)

{
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  FUN_8002b660(param_1,*(undefined *)(param_2 + 0x19));
  return;
}

