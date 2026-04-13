// Function: FUN_80284cd4
// Entry: 80284cd4
// Size: 196 bytes

void FUN_80284cd4(void)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  
  DAT_803df014 = 0;
  DAT_803df018 = 0;
  iVar3 = 7;
  puVar1 = &DAT_803d50d8;
  DAT_803df01c = &DAT_803d50c8;
  uVar2 = 1;
  do {
    puVar1[-4] = puVar1;
    *puVar1 = puVar1 + 4;
    puVar1[4] = puVar1 + 8;
    puVar1[8] = puVar1 + 0xc;
    uVar2 = uVar2 + 8;
    puVar1[0xc] = puVar1 + 0x10;
    puVar1[0x10] = puVar1 + 0x14;
    puVar1[0x14] = puVar1 + 0x18;
    puVar1[0x18] = puVar1 + 0x1c;
    puVar1 = puVar1 + 0x20;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  puVar1 = &DAT_803d50c8 + uVar2 * 4;
  iVar3 = 0x40 - uVar2;
  if (uVar2 < 0x40) {
    do {
      puVar1[-4] = puVar1;
      puVar1 = puVar1 + 4;
      uVar2 = uVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  *(undefined4 *)(uVar2 * 0x10 + -0x7fc2af48) = 0;
  DAT_803df008 = DAT_803df000;
  return;
}

