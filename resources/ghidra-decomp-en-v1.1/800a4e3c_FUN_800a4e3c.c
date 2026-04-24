// Function: FUN_800a4e3c
// Entry: 800a4e3c
// Size: 136 bytes

void FUN_800a4e3c(void)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_8039cf20;
  do {
    if (*puVar2 != 0) {
      FUN_800238c4(*puVar2);
    }
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 7);
  if (DAT_803ddf24 != 0) {
    FUN_80054484();
  }
  if (DAT_803ddf28 != 0) {
    FUN_80054484();
  }
  return;
}

