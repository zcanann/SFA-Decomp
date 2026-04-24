// Function: FUN_8025b5b8
// Entry: 8025b5b8
// Size: 312 bytes

void FUN_8025b5b8(int param_1,int param_2,uint param_3)

{
  if (param_1 == 2) {
    *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xffff8fff | param_3 << 0xc;
    *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xfffc7fff | param_2 << 0xf;
  }
  else if (param_1 < 2) {
    if (param_1 == 0) {
      *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xfffffff8 | param_3;
      *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xffffffc7 | param_2 << 3;
    }
    else if (-1 < param_1) {
      *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xfffffe3f | param_3 << 6;
      *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xfffff1ff | param_2 << 9;
    }
  }
  else if (param_1 < 4) {
    *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xffe3ffff | param_3 << 0x12
    ;
    *(uint *)(DAT_803dc5a8 + 0x120) = *(uint *)(DAT_803dc5a8 + 0x120) & 0xff1fffff | param_2 << 0x15
    ;
  }
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x120));
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 3;
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

