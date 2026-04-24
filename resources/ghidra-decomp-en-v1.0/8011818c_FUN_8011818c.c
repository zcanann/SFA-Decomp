// Function: FUN_8011818c
// Entry: 8011818c
// Size: 108 bytes

void FUN_8011818c(void)

{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  if (DAT_803dd660 != 0) {
    while( true ) {
      iVar1 = FUN_80244128(&DAT_803a5ccc,local_18,0);
      iVar2 = local_18[0];
      if (iVar1 != 1) {
        iVar2 = 0;
      }
      if (iVar2 == 0) break;
      FUN_80119768();
    }
  }
  return;
}

