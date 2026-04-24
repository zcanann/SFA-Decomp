// Function: FUN_80258a14
// Entry: 80258a14
// Size: 88 bytes

void FUN_80258a14(uint param_1,int param_2)

{
  *(uint *)(DAT_803dc5a8 + 0x7c) = param_1 & 0xff | *(uint *)(DAT_803dc5a8 + 0x7c) & 0xffffff00;
  *(uint *)(DAT_803dc5a8 + 0x7c) = *(uint *)(DAT_803dc5a8 + 0x7c) & 0xfff8ffff | param_2 << 0x10;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x7c));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

