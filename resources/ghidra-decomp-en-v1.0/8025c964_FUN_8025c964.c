// Function: FUN_8025c964
// Entry: 8025c964
// Size: 56 bytes

void FUN_8025c964(uint param_1,uint param_2)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_2 & 0xfd | (param_1 & 0xff) << 1 | 0x44000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

