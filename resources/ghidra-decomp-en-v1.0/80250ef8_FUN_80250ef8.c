// Function: FUN_80250ef8
// Entry: 80250ef8
// Size: 20 bytes

void FUN_80250ef8(undefined4 param_1)

{
  write_volatile_2(DAT_cc005000,(short)((uint)param_1 >> 0x10));
  write_volatile_2(DAT_cc005002,(short)param_1);
  return;
}

