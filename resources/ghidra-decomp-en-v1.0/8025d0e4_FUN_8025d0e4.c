// Function: FUN_8025d0e4
// Entry: 8025d0e4
// Size: 64 bytes

void FUN_8025d0e4(undefined4 param_1,int param_2)

{
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,param_2 * 3 + 0x400U | 0x80000);
  FUN_8025d050(param_1,&DAT_cc008000);
  return;
}

