// Function: FUN_80256820
// Entry: 80256820
// Size: 344 bytes

void FUN_80256820(void)

{
  int iVar1;
  uint uVar2;
  
  if (*(char *)(DAT_803dc5a8 + 0x41d) == '\0') {
    if (*(char *)(DAT_803dc5a8 + 0x41c) == '\0') {
      iVar1 = 0;
    }
    else {
      iVar1 = 1;
    }
  }
  else {
    iVar1 = 2;
  }
  uVar2 = *(uint *)(DAT_803dc5a8 + 0x18);
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,0x1008);
  write_volatile_4(0xcc008000,
                   ((uint)((uVar2 & 3) != 0) + (uint)((uVar2 >> 2 & 3) != 0) +
                    (uint)((uVar2 >> 4 & 3) != 0) + (uint)((uVar2 >> 6 & 3) != 0) +
                    (uint)((uVar2 >> 8 & 3) != 0) + (uint)((uVar2 >> 10 & 3) != 0) +
                    (uint)((uVar2 >> 0xc & 3) != 0) + (uint)((uVar2 >> 0xe & 3) != 0)) * 0x10 |
                   (uint)((*(uint *)(DAT_803dc5a8 + 0x14) >> 0xd & 3) != 0) +
                   (uint)((*(uint *)(DAT_803dc5a8 + 0x14) >> 0xf & 3) != 0) | iVar1 << 2);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  return;
}

