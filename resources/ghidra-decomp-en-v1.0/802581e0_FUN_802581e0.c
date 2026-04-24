// Function: FUN_802581e0
// Entry: 802581e0
// Size: 72 bytes

void FUN_802581e0(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x204) = *(uint *)(DAT_803dc5a8 + 0x204) & 0xfffffff0 | param_1 & 0xff;
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,0x103f);
  write_volatile_4(0xcc008000,param_1 & 0xff);
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 4;
  return;
}

