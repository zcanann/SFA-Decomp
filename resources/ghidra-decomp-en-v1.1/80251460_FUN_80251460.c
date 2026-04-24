// Function: FUN_80251460
// Entry: 80251460
// Size: 104 bytes

void FUN_80251460(void)

{
  if (DAT_803decdc != 1) {
    DAT_803decc0 = 0;
    DAT_803decb8 = 0;
    DAT_803decd8 = 0x1000;
    FUN_80250704(&LAB_80251394);
    DAT_803decc8 = 0;
    DAT_803deccc = 0;
    DAT_803decd0 = 0;
    DAT_803decd4 = 0;
    DAT_803decdc = 1;
  }
  return;
}

