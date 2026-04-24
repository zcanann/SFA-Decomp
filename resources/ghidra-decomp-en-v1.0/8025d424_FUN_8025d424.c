// Function: FUN_8025d424
// Entry: 8025d424
// Size: 68 bytes

void FUN_8025d424(int param_1,int param_2)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (param_1 + 0x156U >> 1 & 0x7ff003ff | (param_2 + 0x156U >> 1) << 10) & 0xffffff |
                   0x59000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

