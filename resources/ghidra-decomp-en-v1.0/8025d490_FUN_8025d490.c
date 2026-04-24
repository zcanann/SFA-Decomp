// Function: FUN_8025d490
// Entry: 8025d490
// Size: 132 bytes

void FUN_8025d490(int param_1)

{
  if (param_1 < 5) {
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x30);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x80));
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1018);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x80));
  }
  else {
    write_volatile_1(DAT_cc008000,8);
    write_volatile_1(DAT_cc008000,0x40);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x84));
    write_volatile_1(DAT_cc008000,0x10);
    write_volatile_4(0xcc008000,0x1019);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x84));
  }
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  return;
}

