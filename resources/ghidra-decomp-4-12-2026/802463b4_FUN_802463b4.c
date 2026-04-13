// Function: FUN_802463b4
// Entry: 802463b4
// Size: 296 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_802463b4(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  DAT_803ae770 = 2;
  DAT_803ae772 = 1;
  DAT_803ae77c = 0x10;
  DAT_803ae778 = 0x10;
  DAT_803ae774 = 0;
  DAT_803ae780 = 0xffffffff;
  DAT_803ae798 = 0;
  FUN_802464dc((undefined4 *)&DAT_803ae790);
  DAT_803ae7a0 = 0;
  DAT_803ae79c = 0;
  DAT_800000d8 = &DAT_803ae4a8;
  FUN_80242b6c(-0x7fc51b58);
  FUN_802429a4(0x803ae4a8);
  DAT_803ae7ac = 0x803f90f8;
  DAT_803ae7b0 = &DAT_803e90f8;
  iVar1 = 0;
  _DAT_803e90f8 = 0xdeadbabe;
  puVar2 = (undefined4 *)&DAT_803ae098;
  DAT_803deb08 = 0;
  DAT_800000e4 = &DAT_803ae4a8;
  DAT_803deb0c = 0;
  do {
    FUN_802464dc(puVar2);
    iVar1 = iVar1 + 1;
    puVar2 = puVar2 + 2;
  } while (iVar1 < 0x20);
  FUN_802464dc(&DAT_800000dc);
  if (DAT_800000e0 == (undefined *)0x0) {
    DAT_800000dc = &DAT_803ae4a8;
  }
  else {
    *(undefined **)((int)DAT_800000e0 + 0x2fc) = &DAT_803ae4a8;
  }
  DAT_803ae7a8 = (int)DAT_800000e0;
  DAT_803ae7a4 = 0;
  DAT_800000e0 = &DAT_803ae4a8;
  FUN_80242b6c(-0x7fc51848);
  DAT_803deb10 = 0;
  return;
}

