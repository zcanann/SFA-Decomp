// Function: FUN_80188400
// Entry: 80188400
// Size: 128 bytes

void FUN_80188400(short *param_1,int param_2)

{
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  (**(code **)(*DAT_803dd740 + 4))(param_1,*(undefined4 *)(param_1 + 0x5c),0x21);
  (**(code **)(*DAT_803dd740 + 0x2c))(*(undefined4 *)(param_1 + 0x5c),1);
  return;
}

