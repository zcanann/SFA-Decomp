// Function: FUN_8025d160
// Entry: 8025d160
// Size: 132 bytes

void FUN_8025d160(undefined4 param_1,uint param_2,int param_3)

{
  int iVar1;
  
  if (param_2 < 0x40) {
    param_2 = param_2 << 2;
  }
  else {
    param_2 = (param_2 - 0x40) * 4 + 0x500;
  }
  if (param_3 == 1) {
    iVar1 = 8;
  }
  else {
    iVar1 = 0xc;
  }
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,param_2 | (iVar1 + -1) * 0x10000);
  if (param_3 == 0) {
    FUN_8025d01c(param_1,&DAT_cc008000);
  }
  else {
    FUN_8025d084(param_1,&DAT_cc008000);
  }
  return;
}

