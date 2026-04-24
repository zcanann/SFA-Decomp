// Function: FUN_802560f0
// Entry: 802560f0
// Size: 376 bytes

void FUN_802560f0(undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8024377c();
  FUN_80256614();
  FUN_8025667c(0,0);
  DAT_803de0bc = param_1;
  *(short *)(DAT_803de0ac + 0x20) = (short)*param_1;
  *(short *)(DAT_803de0ac + 0x24) = (short)param_1[1];
  *(short *)(DAT_803de0ac + 0x30) = (short)param_1[7];
  *(short *)(DAT_803de0ac + 0x34) = (short)param_1[6];
  *(short *)(DAT_803de0ac + 0x38) = (short)param_1[5];
  *(short *)(DAT_803de0ac + 0x28) = (short)param_1[3];
  *(short *)(DAT_803de0ac + 0x2c) = (short)param_1[4];
  *(ushort *)(DAT_803de0ac + 0x22) = (ushort)((uint)*param_1 >> 0x10) & 0x3fff;
  *(ushort *)(DAT_803de0ac + 0x26) = (ushort)((uint)param_1[1] >> 0x10) & 0x3fff;
  *(short *)(DAT_803de0ac + 0x32) = (short)((uint)param_1[7] >> 0x10);
  *(ushort *)(DAT_803de0ac + 0x36) = (ushort)((uint)param_1[6] >> 0x10) & 0x3fff;
  *(ushort *)(DAT_803de0ac + 0x3a) = (ushort)((uint)param_1[5] >> 0x10) & 0x3fff;
  *(short *)(DAT_803de0ac + 0x2a) = (short)((uint)param_1[3] >> 0x10);
  *(short *)(DAT_803de0ac + 0x2e) = (short)((uint)param_1[4] >> 0x10);
  sync(0);
  if (DAT_803de0b8 == DAT_803de0bc) {
    DAT_803de0c4 = 1;
    FUN_8025667c(1,0);
    FUN_80256638(1);
  }
  else {
    DAT_803de0c4 = 0;
    FUN_8025667c(0,0);
    FUN_80256638(0);
  }
  FUN_802566c8(1,1);
  FUN_802565ec();
  FUN_802437a4(uVar1);
  return;
}

