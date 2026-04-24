// Function: FUN_80118324
// Entry: 80118324
// Size: 328 bytes

undefined4 FUN_80118324(void)

{
  uint uVar1;
  int iVar2;
  int extraout_r4;
  int extraout_r4_00;
  
  if ((DAT_803a5dfe & 2) == 0) {
    if ((DAT_803a5dfe & 4) == 0) {
      uVar1 = (uint)(FLOAT_803e1d50 * DAT_803a5dac);
      iVar2 = FUN_8024d900();
      if (iVar2 == 1) {
        FUN_8028622c((int)((ulonglong)DAT_803a5e24 * (ulonglong)uVar1 >> 0x20) +
                     DAT_803a5e20 * uVar1 + DAT_803a5e24 * ((int)uVar1 >> 0x1f),DAT_803a5e24 * uVar1
                     ,0,5000);
        DAT_803a5e2c = extraout_r4;
      }
      else {
        FUN_8028622c((int)((ulonglong)DAT_803a5e24 * (ulonglong)uVar1 >> 0x20) +
                     DAT_803a5e20 * uVar1 + DAT_803a5e24 * ((int)uVar1 >> 0x1f),DAT_803a5e24 * uVar1
                     ,0,0x176a);
        DAT_803a5e2c = extraout_r4_00;
      }
      if (DAT_803a5e28 != DAT_803a5e2c) {
        DAT_803a5e28 = DAT_803a5e2c;
        return 1;
      }
    }
    else {
      iVar2 = FUN_8024d7c0();
      if (iVar2 == 1) {
        return 1;
      }
    }
  }
  else {
    iVar2 = FUN_8024d7c0();
    if (iVar2 == 0) {
      return 1;
    }
  }
  return 0;
}

