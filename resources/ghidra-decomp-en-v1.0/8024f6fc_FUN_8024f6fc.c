// Function: FUN_8024f6fc
// Entry: 8024f6fc
// Size: 136 bytes

void FUN_8024f6fc(undefined4 param_1,uint param_2)

{
  ushort uVar1;
  
  FUN_8024377c();
  uVar1 = read_volatile_2(DAT_cc005030);
  write_volatile_2(DAT_cc005030,uVar1 & 0xfc00 | (ushort)((uint)param_1 >> 0x10));
  uVar1 = read_volatile_2(DAT_cc005032);
  write_volatile_2(DAT_cc005032,uVar1 & 0x1f | (ushort)param_1);
  uVar1 = read_volatile_2(DAT_cc005036);
  write_volatile_2(DAT_cc005036,uVar1 & 0x8000 | (ushort)(param_2 >> 5));
  FUN_802437a4();
  return;
}

