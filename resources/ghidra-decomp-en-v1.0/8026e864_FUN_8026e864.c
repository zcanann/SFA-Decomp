// Function: FUN_8026e864
// Entry: 8026e864
// Size: 168 bytes

void FUN_8026e864(void)

{
  int iVar1;
  uint uVar2;
  
  if (*(int *)(DAT_803de218 + 0x14e4) == 0) {
    uVar2 = 0;
    do {
      iVar1 = FUN_8026de58(uVar2 & 0xff);
      if (iVar1 != 0) {
        FUN_8026e070(DAT_803de218 + 0x14e8,iVar1);
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x40);
  }
  else {
    uVar2 = 0;
    do {
      iVar1 = FUN_8026de58(uVar2 & 0xff);
      if (iVar1 != 0) {
        FUN_8026e070(DAT_803de218 +
                     (uint)*(byte *)(*(int *)(DAT_803de218 + 0x14e4) + uVar2) * 0x38 + 0x14e8,iVar1)
        ;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x40);
  }
  return;
}

