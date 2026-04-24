// Function: FUN_8025c7a4
// Entry: 8025c7a4
// Size: 132 bytes

void FUN_8025c7a4(uint param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  if (param_2 == 0x13) {
    uVar1 = 1;
  }
  else {
    if (param_2 < 0x13) {
      if (param_2 == 0x11) {
        uVar1 = 0;
        goto LAB_8025c7ec;
      }
    }
    else if (param_2 == 0x16) {
      uVar1 = 2;
      goto LAB_8025c7ec;
    }
    uVar1 = 2;
  }
LAB_8025c7ec:
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_3 & 0xffffff | 0xf4000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar1 | (param_1 & 0x3fffff) << 2 | 0xf5000000;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

