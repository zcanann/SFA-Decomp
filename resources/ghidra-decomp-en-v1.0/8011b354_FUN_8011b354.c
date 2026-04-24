// Function: FUN_8011b354
// Entry: 8011b354
// Size: 96 bytes

void FUN_8011b354(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_803a8658;
  do {
    FUN_80023800(*puVar2);
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 10);
  return;
}

