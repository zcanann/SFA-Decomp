// Function: FUN_8025ced8
// Entry: 8025ced8
// Size: 112 bytes

void FUN_8025ced8(undefined4 param_1,undefined4 param_2)

{
  if (DAT_803dc5a8[0x13d] != 0) {
    FUN_802587fc();
  }
  if (*DAT_803dc5a8 == 0) {
    FUN_8025898c();
  }
  write_volatile_1(DAT_cc008000,0x40);
  write_volatile_4(0xcc008000,param_1);
  write_volatile_4(0xcc008000,param_2);
  return;
}

