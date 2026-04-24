// Function: FUN_80250cfc
// Entry: 80250cfc
// Size: 104 bytes

void FUN_80250cfc(void)

{
  if (DAT_803de05c != 1) {
    DAT_803de040 = 0;
    DAT_803de038 = 0;
    DAT_803de058 = 0x1000;
    FUN_8024ffa0(&LAB_80250c30);
    DAT_803de048 = 0;
    DAT_803de04c = 0;
    DAT_803de050 = 0;
    DAT_803de054 = 0;
    DAT_803de05c = 1;
  }
  return;
}

