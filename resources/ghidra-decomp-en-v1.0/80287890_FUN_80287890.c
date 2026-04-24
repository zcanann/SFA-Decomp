// Function: FUN_80287890
// Entry: 80287890
// Size: 116 bytes

undefined4 FUN_80287890(void)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = &DAT_803d6920;
  iVar1 = 0;
  do {
    FUN_8028af04(puVar2);
    FUN_8028aefc(puVar2);
    *(undefined4 *)(puVar2 + 4) = 0;
    FUN_8028aef4(puVar2);
    iVar1 = iVar1 + 1;
    puVar2 = puVar2 + 0x890;
  } while (iVar1 < 3);
  return 0;
}

