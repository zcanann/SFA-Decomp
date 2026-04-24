// Function: FUN_80069990
// Entry: 80069990
// Size: 396 bytes

void FUN_80069990(void)

{
  int iVar1;
  int iVar2;
  
  if (DAT_803dcf30 == 0) {
    DAT_803dcf30 = FUN_80023cc8(0x16440,0xffff00ff,0);
    DAT_803dcf34 = FUN_80023cc8(24000,0xffff00ff,0);
    DAT_803dcf38 = FUN_80023cc8(0x4fb0,0xffff00ff,0);
    DAT_803dcf3c = FUN_80023cc8(3000,0xffff00ff,0);
    DAT_803dcf48 = FUN_80023cc8(0x600,0xffff00ff,0);
  }
  iVar1 = 0;
  iVar2 = 4;
  do {
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x14) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x2c) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x44) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x5c) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x74) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x8c) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0xa4) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0xbc) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0xd4) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0xec) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x104) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x11c) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x134) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x14c) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x164) = 0;
    *(undefined *)(DAT_803dcf48 + iVar1 + 0x17c) = 0;
    iVar1 = iVar1 + 0x180;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  DAT_803dcf4e = 0;
  DAT_803dcf4f = 0;
  DAT_803dcf5c = 0;
  DAT_803dcf5e = 0;
  return;
}

