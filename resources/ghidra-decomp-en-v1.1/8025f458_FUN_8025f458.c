// Function: FUN_8025f458
// Entry: 8025f458
// Size: 156 bytes

void FUN_8025f458(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = &DAT_803afe40;
  if ((DAT_803aff4c == 0) || (DAT_803b005c == 0)) {
    FUN_80251670();
    FUN_8024142c();
    iVar1 = 0;
    do {
      puVar2[1] = 0xfffffffd;
      FUN_802464dc(puVar2 + 0x23);
      FUN_80241478(puVar2 + 0x38);
      iVar1 = iVar1 + 1;
      puVar2 = puVar2 + 0x44;
    } while (iVar1 < 2);
    FUN_8025f4f4(&DAT_80000000);
    FUN_80244e64(-0x7fcd07e8);
  }
  return;
}

