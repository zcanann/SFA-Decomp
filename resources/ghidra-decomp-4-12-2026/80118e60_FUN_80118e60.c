// Function: FUN_80118e60
// Entry: 80118e60
// Size: 208 bytes

void FUN_80118e60(void)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  
  puVar3 = &DAT_803a69c0;
  if (DAT_803a6a68 == 0) {
    iVar1 = 0;
    do {
      FUN_80119764(puVar3 + 0xf4);
      puVar3 = puVar3 + 8;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 10);
  }
  iVar1 = 0;
  puVar2 = &DAT_803a69c0;
  puVar3 = puVar2;
  do {
    FUN_80119a10(puVar3 + 0x144);
    puVar3 = puVar3 + 0x10;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 3);
  if (DAT_803a6a5f != '\0') {
    iVar1 = 0;
    do {
      FUN_801175f8(puVar2 + 0x174);
      puVar2 = puVar2 + 0x10;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 3);
  }
  FUN_802446f8((undefined4 *)&DAT_803a694c,&DAT_803de2fc,1);
  return;
}

