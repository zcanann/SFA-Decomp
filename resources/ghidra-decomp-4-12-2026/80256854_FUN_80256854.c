// Function: FUN_80256854
// Entry: 80256854
// Size: 376 bytes

void FUN_80256854(undefined4 *param_1)

{
  FUN_80243e74();
  FUN_80256d78();
  FUN_80256de0(0,0);
  DAT_803ded3c = param_1;
  *(short *)(DAT_803ded2c + 0x20) = (short)*param_1;
  *(short *)(DAT_803ded2c + 0x24) = (short)param_1[1];
  *(short *)(DAT_803ded2c + 0x30) = (short)param_1[7];
  *(short *)(DAT_803ded2c + 0x34) = (short)param_1[6];
  *(short *)(DAT_803ded2c + 0x38) = (short)param_1[5];
  *(short *)(DAT_803ded2c + 0x28) = (short)param_1[3];
  *(short *)(DAT_803ded2c + 0x2c) = (short)param_1[4];
  *(ushort *)(DAT_803ded2c + 0x22) = (ushort)((uint)*param_1 >> 0x10) & 0x3fff;
  *(ushort *)(DAT_803ded2c + 0x26) = (ushort)((uint)param_1[1] >> 0x10) & 0x3fff;
  *(short *)(DAT_803ded2c + 0x32) = (short)((uint)param_1[7] >> 0x10);
  *(ushort *)(DAT_803ded2c + 0x36) = (ushort)((uint)param_1[6] >> 0x10) & 0x3fff;
  *(ushort *)(DAT_803ded2c + 0x3a) = (ushort)((uint)param_1[5] >> 0x10) & 0x3fff;
  *(short *)(DAT_803ded2c + 0x2a) = (short)((uint)param_1[3] >> 0x10);
  *(short *)(DAT_803ded2c + 0x2e) = (short)((uint)param_1[4] >> 0x10);
  sync(0);
  if (DAT_803ded38 == DAT_803ded3c) {
    DAT_803ded44 = 1;
    FUN_80256de0(1,0);
    FUN_80256d9c('\x01');
  }
  else {
    DAT_803ded44 = 0;
    FUN_80256de0(0,0);
    FUN_80256d9c('\0');
  }
  FUN_80256e2c(1,1);
  FUN_80256d50();
  FUN_80243e9c();
  return;
}

