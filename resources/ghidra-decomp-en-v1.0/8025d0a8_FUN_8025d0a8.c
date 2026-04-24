// Function: FUN_8025d0a8
// Entry: 8025d0a8
// Size: 60 bytes

void FUN_8025d0a8(undefined4 param_1,int param_2)

{
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,param_2 << 2 | 0xb0000);
  FUN_8025d01c(param_1,&DAT_cc008000);
  return;
}

