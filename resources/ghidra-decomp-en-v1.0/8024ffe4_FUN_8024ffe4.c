// Function: FUN_8024ffe4
// Entry: 8024ffe4
// Size: 240 bytes

void FUN_8024ffe4(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  ushort uVar1;
  
  FUN_8024377c();
  uVar1 = read_volatile_2(DAT_cc005020);
  write_volatile_2(DAT_cc005020,uVar1 & 0xfc00 | (ushort)((uint)param_2 >> 0x10));
  uVar1 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar1 & 0x1f | (ushort)param_2);
  uVar1 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar1 & 0xfc00 | (ushort)((uint)param_3 >> 0x10));
  uVar1 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar1 & 0x1f | (ushort)param_3);
  uVar1 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,(ushort)(param_1 << 0xf) | uVar1 & 0x7fff);
  uVar1 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar1 & 0xfc00 | (ushort)((uint)param_4 >> 0x10));
  uVar1 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar1 & 0x1f | (ushort)param_4);
  FUN_802437a4();
  return;
}

