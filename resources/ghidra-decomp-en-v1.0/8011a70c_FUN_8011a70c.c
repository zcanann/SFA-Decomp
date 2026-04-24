// Function: FUN_8011a70c
// Entry: 8011a70c
// Size: 216 bytes

void FUN_8011a70c(void)

{
  int iVar1;
  int iVar2;
  
  DAT_803dd6b0 = DAT_803dd6a8;
  DAT_803db9fc = 0;
  if ((DAT_803db424 != '\0') && (FUN_800e8d9c(), DAT_803db424 != '\0')) {
    DAT_803db9fc = 3;
  }
  iVar2 = DAT_803db9fc * 0x24;
  for (iVar1 = DAT_803db9fc; iVar1 < 3; iVar1 = iVar1 + 1) {
    FUN_8028f688(DAT_803dd6b0 + iVar2,&DAT_803dba1c,&DAT_803dba20);
    *(undefined *)(DAT_803dd6b0 + iVar2 + 5) = 0;
    *(undefined *)(DAT_803dd6b0 + iVar2 + 6) = 0;
    *(undefined *)(DAT_803dd6b0 + iVar2 + 4) = 0;
    *(undefined4 *)(DAT_803dd6b0 + iVar2 + 8) = 0;
    *(undefined *)(DAT_803dd6b0 + iVar2 + 0x21) = 0;
    iVar2 = iVar2 + 0x24;
  }
  return;
}

