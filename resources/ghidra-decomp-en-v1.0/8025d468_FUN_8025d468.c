// Function: FUN_8025d468
// Entry: 8025d468
// Size: 40 bytes

void FUN_8025d468(undefined4 param_1)

{
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,0x1005);
  write_volatile_4(0xcc008000,param_1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  return;
}

