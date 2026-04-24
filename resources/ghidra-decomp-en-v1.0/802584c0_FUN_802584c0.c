// Function: FUN_802584c0
// Entry: 802584c0
// Size: 36 bytes

void FUN_802584c0(void)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1dc));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

