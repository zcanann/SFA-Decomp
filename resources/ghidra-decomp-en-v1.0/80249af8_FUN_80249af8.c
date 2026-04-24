// Function: FUN_80249af8
// Entry: 80249af8
// Size: 228 bytes

void FUN_80249af8(void)

{
  int iVar1;
  
  if (DAT_803ddf24 == 3) {
    iVar1 = FUN_8028f228(&DAT_803adf00,*(undefined4 *)(DAT_803ddf08 + 0x24),0x1c);
    if (iVar1 == 0) {
      FUN_80003494(DAT_803ddf0c,&DAT_803adf00,0x20);
      *(undefined4 *)(DAT_803ddf08 + 0xc) = 1;
      FUN_802419b8(&DAT_803adf00,0x20);
      DAT_803ddf4c = FUN_80249c10;
      FUN_80249c10(DAT_803ddf08);
    }
    else {
      FUN_802483d0(&LAB_80249c48);
    }
  }
  else {
    iVar1 = FUN_8028f228(&DAT_803adf00,DAT_803ddf0c,0x20);
    if (iVar1 == 0) {
      DAT_803ddf4c = FUN_80249bdc;
      FUN_80249bdc(DAT_803ddf08);
    }
    else {
      FUN_802483d0(&LAB_80249c48);
    }
  }
  return;
}

