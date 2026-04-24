// Function: FUN_8018acd8
// Entry: 8018acd8
// Size: 212 bytes

void FUN_8018acd8(undefined2 *param_1)

{
  uint uVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_8018a8bc;
  *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x18) << 8);
  if (*(short *)(*(int *)(param_1 + 0x26) + 0x1e) == -1) {
    *pbVar2 = *pbVar2 & 0x7f;
  }
  else {
    uVar1 = FUN_8001ffb4();
    *pbVar2 = (byte)((uVar1 & 0xff) << 7) | *pbVar2 & 0x7f;
  }
  if ((char)*pbVar2 < '\0') {
    param_1[3] = param_1[3] | 0x4000;
    FUN_80035f00(param_1);
  }
  DAT_803ddae0 = FUN_80013ec8(0x5a,1);
  *pbVar2 = *pbVar2 & 0xbf | 0x40;
  return;
}

