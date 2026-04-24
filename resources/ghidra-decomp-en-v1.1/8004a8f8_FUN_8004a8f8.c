// Function: FUN_8004a8f8
// Entry: 8004a8f8
// Size: 192 bytes

void FUN_8004a8f8(char param_1)

{
  if (param_1 == '\0') {
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x24000000;
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x23000000;
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000._0_2_ = 0;
    DAT_cc008000._0_2_ = 0x1006;
    DAT_cc008000 = 0;
  }
  else {
    FUN_8025dc78(0x23,0x16);
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x2402c004;
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = 0x23000020;
    DAT_cc008000._0_1_ = 0x10;
    DAT_cc008000._0_2_ = 0;
    DAT_cc008000._0_2_ = 0x1006;
    DAT_cc008000 = 0x84400;
  }
  return;
}

