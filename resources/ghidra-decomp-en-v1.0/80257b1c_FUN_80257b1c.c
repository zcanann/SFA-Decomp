// Function: FUN_80257b1c
// Entry: 80257b1c
// Size: 156 bytes

void FUN_80257b1c(void)

{
  int iVar1;
  byte bVar2;
  
  bVar2 = 0;
  iVar1 = 0;
  while( true ) {
    if (7 < bVar2) break;
    if (((uint)*(byte *)(DAT_803dc5a8 + 0x4f2) & 1 << (uint)bVar2) != 0) {
      write_volatile_1(DAT_cc008000,8);
      write_volatile_1(DAT_cc008000,bVar2 | 0x70);
      write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + iVar1 + 0x1c));
      write_volatile_1(DAT_cc008000,8);
      write_volatile_1(DAT_cc008000,bVar2 | 0x80);
      write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + iVar1 + 0x3c));
      write_volatile_1(DAT_cc008000,8);
      write_volatile_1(DAT_cc008000,bVar2 | 0x90);
      write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + iVar1 + 0x5c));
    }
    iVar1 = iVar1 + 4;
    bVar2 = bVar2 + 1;
  }
  *(undefined *)(DAT_803dc5a8 + 0x4f2) = 0;
  return;
}

