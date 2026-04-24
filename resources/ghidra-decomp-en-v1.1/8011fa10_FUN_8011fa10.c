// Function: FUN_8011fa10
// Entry: 8011fa10
// Size: 152 bytes

void FUN_8011fa10(void)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = DAT_803de450;
  if (DAT_803de450 != 0) {
    *(undefined *)(DAT_803de450 + 0x18) = 0;
    iVar2 = *(int *)(uVar1 + 0x40);
    if (iVar2 == 1) {
      FUN_80054484();
      FUN_80054484();
      FUN_80054484();
      FUN_80054484();
    }
    else if ((iVar2 < 1) && (-1 < iVar2)) {
      FUN_80054484();
      FUN_80054484();
    }
    FUN_800238c4(DAT_803de450);
    DAT_803de450 = 0;
  }
  return;
}

