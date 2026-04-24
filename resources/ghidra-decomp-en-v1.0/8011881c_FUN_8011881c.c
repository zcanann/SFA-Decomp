// Function: FUN_8011881c
// Entry: 8011881c
// Size: 228 bytes

void FUN_8011881c(void)

{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  if ((DAT_803a5df8 != 0) && (DAT_803a5dfc != '\0')) {
    DAT_803a5dfd = 0;
    DAT_803a5dfc = '\0';
    FUN_8024c1ac(DAT_803dd664);
    if (DAT_803a5e08 == 0) {
      FUN_8024b698();
      FUN_80119618();
    }
    FUN_80119ae8();
    if (DAT_803a5dff != '\0') {
      FUN_80117534();
    }
    do {
      iVar2 = FUN_80244128(&DAT_803a5ccc,local_18,0);
      iVar1 = local_18[0];
      if (iVar2 != 1) {
        iVar1 = 0;
      }
    } while (iVar1 != 0);
    DAT_803a5e34 = DAT_803a5e38;
    DAT_803a5e40 = 0;
    DAT_803a5e00 = 0;
    DAT_803a5e04 = 0;
  }
  return;
}

