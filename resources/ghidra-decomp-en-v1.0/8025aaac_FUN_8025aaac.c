// Function: FUN_8025aaac
// Entry: 8025aaac
// Size: 72 bytes

void FUN_8025aaac(void)

{
  FUN_8025b878();
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,0x66001000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,0x66001100);
  FUN_8025b878();
  return;
}

