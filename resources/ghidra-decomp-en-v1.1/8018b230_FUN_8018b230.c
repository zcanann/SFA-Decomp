// Function: FUN_8018b230
// Entry: 8018b230
// Size: 212 bytes

void FUN_8018b230(undefined2 *param_1)

{
  uint uVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_8018ae14;
  *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x18) << 8);
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x26) + 0x1e);
  if (uVar1 == 0xffffffff) {
    *pbVar2 = *pbVar2 & 0x7f;
  }
  else {
    uVar1 = FUN_80020078(uVar1);
    *pbVar2 = (byte)((uVar1 & 0xff) << 7) | *pbVar2 & 0x7f;
  }
  if ((char)*pbVar2 < '\0') {
    param_1[3] = param_1[3] | 0x4000;
    FUN_80035ff8((int)param_1);
  }
  DAT_803de760 = FUN_80013ee8(0x5a);
  *pbVar2 = *pbVar2 & 0xbf | 0x40;
  return;
}

