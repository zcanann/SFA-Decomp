// Function: FUN_8016f454
// Entry: 8016f454
// Size: 128 bytes

void FUN_8016f454(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (DAT_803de728 != 0) {
    iVar1 = 0;
    puVar2 = &DAT_803de728;
    do {
      FUN_80054484();
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 2);
  }
  if (DAT_803de720 != (undefined *)0x0) {
    FUN_80013e4c(DAT_803de720);
    DAT_803de720 = (undefined *)0x0;
  }
  return;
}

