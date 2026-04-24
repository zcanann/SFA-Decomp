// Function: FUN_8025ecf4
// Entry: 8025ecf4
// Size: 156 bytes

void FUN_8025ecf4(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = &DAT_803af1e0;
  if ((DAT_803af2ec == 0) || (DAT_803af3fc == 0)) {
    FUN_80250f0c();
    FUN_80240d34();
    iVar1 = 0;
    do {
      puVar2[1] = 0xfffffffd;
      FUN_80245d78(puVar2 + 0x23);
      FUN_80240d80(puVar2 + 0x38);
      iVar1 = iVar1 + 1;
      puVar2 = puVar2 + 0x44;
    } while (iVar1 < 2);
    FUN_8025ed90(0x80000000);
    FUN_8024476c(&PTR_LAB_8032ebc0);
  }
  return;
}

