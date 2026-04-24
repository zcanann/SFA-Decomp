// Function: FUN_8025889c
// Entry: 8025889c
// Size: 240 bytes

void FUN_8025889c(byte param_1,byte param_2,undefined2 param_3)

{
  if (DAT_803dc5a8[0x13d] != 0) {
    if ((DAT_803dc5a8[0x13d] & 1U) != 0) {
      FUN_8025ae2c();
    }
    if ((DAT_803dc5a8[0x13d] & 2U) != 0) {
      FUN_8025b7ac();
    }
    if ((DAT_803dc5a8[0x13d] & 4U) != 0) {
      FUN_80258bb8();
    }
    if ((DAT_803dc5a8[0x13d] & 8U) != 0) {
      FUN_8025705c();
    }
    if ((DAT_803dc5a8[0x13d] & 0x10U) != 0) {
      FUN_80257b1c();
    }
    if ((DAT_803dc5a8[0x13d] & 0x18U) != 0) {
      FUN_802570b0();
    }
    DAT_803dc5a8[0x13d] = 0;
  }
  if (*DAT_803dc5a8 == 0) {
    FUN_8025898c();
  }
  write_volatile_1(DAT_cc008000,param_2 | param_1);
  write_volatile_2(0xcc008000,param_3);
  return;
}

