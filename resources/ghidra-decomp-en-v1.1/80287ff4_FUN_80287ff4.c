// Function: FUN_80287ff4
// Entry: 80287ff4
// Size: 116 bytes

undefined4 FUN_80287ff4(void)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = &DAT_803d7580;
  iVar1 = 0;
  do {
    FUN_8028b668();
    FUN_8028b660();
    *(undefined4 *)(puVar2 + 4) = 0;
    FUN_8028b658();
    iVar1 = iVar1 + 1;
    puVar2 = puVar2 + 0x890;
  } while (iVar1 < 3);
  return 0;
}

