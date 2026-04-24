// Function: FUN_80259e58
// Entry: 80259e58
// Size: 76 bytes

void FUN_80259e58(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x204) =
       *(uint *)(DAT_803dc5a8 + 0x204) & 0xffffff8f | (param_1 & 0xff) << 4;
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,0x1009);
  write_volatile_4(0xcc008000,param_1 & 0xff);
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 4;
  return;
}

