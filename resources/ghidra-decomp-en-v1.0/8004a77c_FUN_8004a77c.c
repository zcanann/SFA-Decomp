// Function: FUN_8004a77c
// Entry: 8004a77c
// Size: 192 bytes

void FUN_8004a77c(char param_1)

{
  if (param_1 == '\0') {
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x24000000);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x23000000);
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_2(0xcc008000,0);
    write_volatile_2(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0);
  }
  else {
    FUN_8025d514(0x23,0x16);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x2402c004);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,0x23000020);
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_2(0xcc008000,0);
    write_volatile_2(0xcc008000,0x1006);
    write_volatile_4(0xcc008000,0x84400);
  }
  return;
}

