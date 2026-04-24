// Function: FUN_8016efa8
// Entry: 8016efa8
// Size: 128 bytes

void FUN_8016efa8(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (DAT_803ddaa8 != 0) {
    iVar1 = 0;
    puVar2 = &DAT_803ddaa8;
    do {
      FUN_80054308(*puVar2);
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 2);
  }
  if (DAT_803ddaa0 != 0) {
    FUN_80013e2c();
    DAT_803ddaa0 = 0;
  }
  return;
}

