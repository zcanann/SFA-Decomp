// Function: FUN_80069b0c
// Entry: 80069b0c
// Size: 396 bytes

void FUN_80069b0c(void)

{
  int iVar1;
  int iVar2;
  
  if (DAT_803ddbb0 == 0) {
    DAT_803ddbb0 = FUN_80023d8c(0x16440,-0xff01);
    DAT_803ddbb4 = FUN_80023d8c(24000,-0xff01);
    DAT_803ddbb8 = FUN_80023d8c(0x4fb0,-0xff01);
    DAT_803ddbbc = FUN_80023d8c(3000,-0xff01);
    DAT_803ddbc8 = FUN_80023d8c(0x600,-0xff01);
  }
  iVar1 = 0;
  iVar2 = 4;
  do {
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x14) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x2c) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x44) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x5c) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x74) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x8c) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0xa4) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0xbc) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0xd4) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0xec) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x104) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x11c) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x134) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x14c) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x164) = 0;
    *(undefined *)(DAT_803ddbc8 + iVar1 + 0x17c) = 0;
    iVar1 = iVar1 + 0x180;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  DAT_803ddbde = 0;
  DAT_803ddbdc = 0;
  DAT_803ddbce = 0;
  DAT_803ddbcf = 0;
  return;
}

