// Function: FUN_8011b638
// Entry: 8011b638
// Size: 96 bytes

void FUN_8011b638(void)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_803a92b8;
  do {
    FUN_800238c4(*puVar2);
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 10);
  return;
}

