// Function: FUN_8025d8c4
// Entry: 8025d8c4
// Size: 132 bytes

void FUN_8025d8c4(float *param_1,uint param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  
  if (param_2 < 0x40) {
    uVar2 = param_2 << 2;
  }
  else {
    uVar2 = (param_2 - 0x40) * 4 + 0x500;
  }
  if (param_3 == 1) {
    iVar1 = 8;
  }
  else {
    iVar1 = 0xc;
  }
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = uVar2 | (iVar1 + -1) * 0x10000;
  if (param_3 == 0) {
    FUN_8025d780(param_1,(float *)&DAT_cc008000);
  }
  else {
    FUN_8025d7e8(param_1,(float *)&DAT_cc008000);
  }
  return;
}

