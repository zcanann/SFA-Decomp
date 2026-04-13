// Function: FUN_8024a25c
// Entry: 8024a25c
// Size: 228 bytes

void FUN_8024a25c(void)

{
  int iVar1;
  
  if (DAT_803deba4 == 3) {
    iVar1 = FUN_8028f988(-0x7fc514a0,*(int *)(DAT_803deb88 + 0x24),0x1c);
    if (iVar1 == 0) {
      FUN_80003494(DAT_803deb8c,0x803aeb60,0x20);
      *(undefined4 *)(DAT_803deb88 + 0xc) = 1;
      FUN_802420b0(0x803aeb60,0x20);
      DAT_803debcc = FUN_8024a374;
      FUN_8024a374();
    }
    else {
      FUN_80248b34(&LAB_8024a3ac);
    }
  }
  else {
    iVar1 = FUN_8028f988(-0x7fc514a0,DAT_803deb8c,0x20);
    if (iVar1 == 0) {
      DAT_803debcc = FUN_8024a340;
      FUN_8024a340();
    }
    else {
      FUN_80248b34(&LAB_8024a3ac);
    }
  }
  return;
}

