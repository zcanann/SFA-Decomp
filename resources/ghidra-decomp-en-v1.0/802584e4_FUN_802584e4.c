// Function: FUN_802584e4
// Entry: 802584e4
// Size: 36 bytes

void FUN_802584e4(void)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,0x63000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

