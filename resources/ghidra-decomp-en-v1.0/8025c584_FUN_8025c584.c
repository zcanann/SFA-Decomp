// Function: FUN_8025c584
// Entry: 8025c584
// Size: 260 bytes

void FUN_8025c584(int param_1,int param_2,int param_3,int param_4)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 1;
  if ((param_1 != 1) && (param_1 != 3)) {
    uVar2 = 0;
  }
  uVar1 = countLeadingZeros(3 - param_1);
  *(uint *)(DAT_803dc5a8 + 0x1d0) = *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xfffffffe | uVar2;
  uVar2 = countLeadingZeros(2 - param_1);
  *(uint *)(DAT_803dc5a8 + 0x1d0) =
       *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xfffff7ff | (uVar1 & 0x3ffffe0) << 6;
  *(uint *)(DAT_803dc5a8 + 0x1d0) =
       *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xfffffffd | uVar2 >> 4 & 0xffffffe;
  *(uint *)(DAT_803dc5a8 + 0x1d0) = *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xffff0fff | param_4 << 0xc;
  *(uint *)(DAT_803dc5a8 + 0x1d0) = *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xfffff8ff | param_2 << 8;
  *(uint *)(DAT_803dc5a8 + 0x1d0) = *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xffffff1f | param_3 << 5;
  *(uint *)(DAT_803dc5a8 + 0x1d0) = *(uint *)(DAT_803dc5a8 + 0x1d0) & 0xffffff | 0x41000000;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x1d0));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

