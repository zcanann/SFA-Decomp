// Function: FUN_8025c708
// Entry: 8025c708
// Size: 120 bytes

void FUN_8025c708(uint param_1,int param_2,uint param_3)

{
  *(uint *)(DAT_803dc5a8 + 0x1d8) = *(uint *)(DAT_803dc5a8 + 0x1d8) & 0xfffffffe | param_1 & 0xff;
  *(uint *)(DAT_803dc5a8 + 0x1d8) = *(uint *)(DAT_803dc5a8 + 0x1d8) & 0xfffffff1 | param_2 << 1;
  *(uint *)(DAT_803dc5a8 + 0x1d8) =
       *(uint *)(DAT_803dc5a8 + 0x1d8) & 0xffffffef | (param_3 & 0xff) << 4;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d8));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

