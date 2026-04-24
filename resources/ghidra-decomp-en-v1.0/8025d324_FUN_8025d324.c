// Function: FUN_8025d324
// Entry: 8025d324
// Size: 176 bytes

void FUN_8025d324(int param_1,int param_2,int param_3,int param_4)

{
  *(uint *)(DAT_803dc5a8 + 0xf8) = *(uint *)(DAT_803dc5a8 + 0xf8) & 0xfffff800 | param_2 + 0x156U;
  *(uint *)(DAT_803dc5a8 + 0xf8) =
       *(uint *)(DAT_803dc5a8 + 0xf8) & 0xff800fff | (param_1 + 0x156) * 0x1000;
  *(uint *)(DAT_803dc5a8 + 0xfc) =
       *(uint *)(DAT_803dc5a8 + 0xfc) & 0xfffff800 | param_2 + 0x156U + param_4 + -1;
  *(uint *)(DAT_803dc5a8 + 0xfc) =
       *(uint *)(DAT_803dc5a8 + 0xfc) & 0xff800fff | (param_1 + 0x156 + param_3 + -1) * 0x1000;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0xf8));
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0xfc));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

