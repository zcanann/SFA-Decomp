// Function: FUN_8025898c
// Entry: 8025898c
// Size: 136 bytes

void FUN_8025898c(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = (uint)*(ushort *)(DAT_803dc5a8 + 4) * (uint)*(ushort *)(DAT_803dc5a8 + 6);
  write_volatile_1(DAT_cc008000,0x98);
  write_volatile_2(0xcc008000,*(ushort *)(DAT_803dc5a8 + 4));
  uVar1 = iVar3 + 3;
  uVar2 = uVar1 >> 2;
  if (iVar3 != 0) {
    uVar1 = uVar1 >> 5;
    if (uVar1 != 0) {
      do {
        write_volatile_4(0xcc008000,0);
        write_volatile_4(0xcc008000,0);
        write_volatile_4(0xcc008000,0);
        write_volatile_4(0xcc008000,0);
        write_volatile_4(0xcc008000,0);
        write_volatile_4(0xcc008000,0);
        write_volatile_4(0xcc008000,0);
        write_volatile_4(0xcc008000,0);
        uVar1 = uVar1 - 1;
      } while (uVar1 != 0);
      uVar2 = uVar2 & 7;
      if (uVar2 == 0) goto LAB_80258a04;
    }
    do {
      write_volatile_4(0xcc008000,0);
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
LAB_80258a04:
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  return;
}

