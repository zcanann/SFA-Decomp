// Function: FUN_8025d63c
// Entry: 8025d63c
// Size: 112 bytes

void FUN_8025d63c(undefined4 param_1,undefined4 param_2)

{
  if (DAT_803dd210[0x13d] != 0) {
    FUN_80258f60(param_1,param_2,(uint)DAT_803dd210);
  }
  if (*DAT_803dd210 == 0) {
    FUN_802590f0();
  }
  DAT_cc008000._0_1_ = 0x40;
  DAT_cc008000 = param_1;
  DAT_cc008000 = param_2;
  return;
}

