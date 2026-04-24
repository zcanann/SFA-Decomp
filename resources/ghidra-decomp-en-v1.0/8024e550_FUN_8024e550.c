// Function: FUN_8024e550
// Entry: 8024e550
// Size: 260 bytes

undefined4 FUN_8024e550(uint param_1)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = FUN_8024377c();
  uVar3 = (param_1 | DAT_803ddfc8) & ~(DAT_803ddfc0 | DAT_803ddfc4);
  DAT_803ddfb8 = DAT_803ddfb8 | uVar3;
  DAT_803ddfc8 = 0;
  uVar2 = DAT_803ddfb8 & DAT_803ddfb4;
  if ((DAT_800030e3 & 0x40) == 0) {
    DAT_803ddfbc = DAT_803ddfbc | uVar3;
  }
  DAT_803ddfb4 = DAT_803ddfb4 & ~uVar3;
  FUN_802526ec(uVar2);
  if (DAT_803dc588 == 0x20) {
    DAT_803dc588 = countLeadingZeros(DAT_803ddfb8);
    if (DAT_803dc588 != 0x20) {
      DAT_803ddfb8 = DAT_803ddfb8 & ~(0x80000000U >> DAT_803dc588);
      FUN_800033a8(&DAT_803ae1c0 + DAT_803dc588 * 0xc,0,0xc);
      FUN_80252f44(DAT_803dc588,&LAB_8024dff0);
    }
  }
  FUN_802437a4(uVar1);
  return 1;
}

