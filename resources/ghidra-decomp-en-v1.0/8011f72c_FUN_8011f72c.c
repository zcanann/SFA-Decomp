// Function: FUN_8011f72c
// Entry: 8011f72c
// Size: 152 bytes

void FUN_8011f72c(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = DAT_803dd7d0;
  if (DAT_803dd7d0 != 0) {
    *(undefined *)(DAT_803dd7d0 + 0x18) = 0;
    iVar2 = *(int *)(iVar1 + 0x40);
    if (iVar2 == 1) {
      FUN_80054308(*(undefined4 *)(iVar1 + 0x30));
      FUN_80054308(*(undefined4 *)(iVar1 + 0x34));
      FUN_80054308(*(undefined4 *)(iVar1 + 0x38));
      FUN_80054308(*(undefined4 *)(iVar1 + 0x3c));
    }
    else if ((iVar2 < 1) && (-1 < iVar2)) {
      FUN_80054308(*(undefined4 *)(iVar1 + 0x2c));
      FUN_80054308(*(undefined4 *)(iVar1 + 0x30));
    }
    FUN_80023800(DAT_803dd7d0);
    DAT_803dd7d0 = 0;
  }
  return;
}

