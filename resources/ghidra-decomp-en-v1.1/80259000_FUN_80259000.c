// Function: FUN_80259000
// Entry: 80259000
// Size: 240 bytes

void FUN_80259000(byte param_1,undefined4 param_2,uint param_3)

{
  undefined4 extraout_r4;
  undefined4 uVar1;
  uint uVar2;
  
  if (DAT_803dd210[0x13d] != 0) {
    uVar1 = param_2;
    uVar2 = param_3;
    if ((DAT_803dd210[0x13d] & 1U) != 0) {
      FUN_8025b590();
      uVar1 = extraout_r4;
    }
    if ((DAT_803dd210[0x13d] & 2U) != 0) {
      FUN_8025bf10(DAT_803dd210,uVar1,uVar2);
    }
    if ((DAT_803dd210[0x13d] & 4U) != 0) {
      FUN_8025931c();
    }
    if ((DAT_803dd210[0x13d] & 8U) != 0) {
      FUN_802577c0();
    }
    if ((DAT_803dd210[0x13d] & 0x10U) != 0) {
      FUN_80258280();
    }
    if ((DAT_803dd210[0x13d] & 0x18U) != 0) {
      FUN_80257814();
    }
    DAT_803dd210[0x13d] = 0;
  }
  if (*DAT_803dd210 == 0) {
    FUN_802590f0();
  }
  DAT_cc008000._0_1_ = (byte)param_2 | param_1;
  DAT_cc008000._0_2_ = (short)param_3;
  return;
}

