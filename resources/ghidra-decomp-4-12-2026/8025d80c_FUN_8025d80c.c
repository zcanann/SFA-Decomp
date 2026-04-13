// Function: FUN_8025d80c
// Entry: 8025d80c
// Size: 60 bytes

void FUN_8025d80c(float *param_1,int param_2)

{
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = param_2 << 2 | 0xb0000;
  FUN_8025d780(param_1,(float *)&DAT_cc008000);
  return;
}

