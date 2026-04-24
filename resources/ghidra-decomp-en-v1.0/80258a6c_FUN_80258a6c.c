// Function: FUN_80258a6c
// Entry: 80258a6c
// Size: 84 bytes

void FUN_80258a6c(uint param_1,int param_2)

{
  *(uint *)(DAT_803dc5a8 + 0x7c) =
       (param_1 & 0xff) << 8 | *(uint *)(DAT_803dc5a8 + 0x7c) & 0xffff00ff;
  *(uint *)(DAT_803dc5a8 + 0x7c) = *(uint *)(DAT_803dc5a8 + 0x7c) & 0xffc7ffff | param_2 << 0x13;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x7c));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

