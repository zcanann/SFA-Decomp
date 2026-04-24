// Function: FUN_8025c7c0
// Entry: 8025c7c0
// Size: 272 bytes

void FUN_8025c7c0(int param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(DAT_803dc5a8 + 0x1dc);
  *(uint *)(DAT_803dc5a8 + 0x1dc) = uVar1 & 0xfffffff8 | *(uint *)(&DAT_8032eab0 + param_1 * 4);
  *(uint *)(DAT_803dc5a8 + 0x1dc) = *(uint *)(DAT_803dc5a8 + 0x1dc) & 0xffffffc7 | param_2 << 3;
  if (uVar1 != *(uint *)(DAT_803dc5a8 + 0x1dc)) {
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(uint *)(DAT_803dc5a8 + 0x1dc));
    *(uint *)(DAT_803dc5a8 + 0x204) =
         *(uint *)(DAT_803dc5a8 + 0x204) & 0xfffffdff | (uint)(param_1 == 2) << 9;
    *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 4;
  }
  if (*(uint *)(&DAT_8032eab0 + param_1 * 4) == 4) {
    *(uint *)(DAT_803dc5a8 + 0x1d4) =
         (param_1 + -4) * 0x200 & 0x600U | *(uint *)(DAT_803dc5a8 + 0x1d4) & 0xfffff9ff;
    *(uint *)(DAT_803dc5a8 + 0x1d4) = *(uint *)(DAT_803dc5a8 + 0x1d4) & 0xffffff | 0x42000000;
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d4));
  }
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

