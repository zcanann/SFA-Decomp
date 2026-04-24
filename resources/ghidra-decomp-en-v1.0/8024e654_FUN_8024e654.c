// Function: FUN_8024e654
// Entry: 8024e654
// Size: 528 bytes

undefined4 FUN_8024e654(void)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 uVar3;
  short extraout_r4;
  short extraout_r4_00;
  short extraout_r4_01;
  uint uVar4;
  undefined8 uVar5;
  
  if (DAT_803ddfb0 == 0) {
    if (DAT_803ddfd4 != 0) {
      FUN_8024ecb4();
    }
    DAT_803ddfb0 = 1;
    if (DAT_803de088 != 0) {
      uVar5 = FUN_80246c50();
      uVar1 = (undefined4)((ulonglong)uVar5 >> 0x20);
      uVar3 = (undefined4)uVar5;
      FUN_80286490(uVar1,uVar3,0x10);
      FUN_80286490(uVar1,uVar3,0x20);
      FUN_80286490(uVar1,uVar3,0x30);
      DAT_803ddfbc = 0xf0000000;
      DAT_800030e0 = extraout_r4_01 + extraout_r4_00 + (short)uVar5 + extraout_r4 & 0x3fff;
    }
    DAT_803ae1f0 = (DAT_800030e0 & 0x3fff) << 8 | 0x4d000000;
    DAT_803ae1f4 = (DAT_800030e0 & 0x3fff) << 8 | 0x4d400000;
    DAT_803ae1f8 = (DAT_800030e0 & 0x3fff) << 8 | 0x4d800000;
    DAT_803ae1fc = (DAT_800030e0 & 0x3fff) << 8 | 0x4dc00000;
    FUN_80253164();
    FUN_8024476c(&PTR_LAB_8032e0b8);
    uVar1 = FUN_8024377c();
    uVar4 = (DAT_803ddfc8 | 0xf0000000) & ~(DAT_803ddfc0 | DAT_803ddfc4);
    DAT_803ddfb8 = DAT_803ddfb8 | uVar4;
    DAT_803ddfc8 = 0;
    uVar2 = DAT_803ddfb8 & DAT_803ddfb4;
    if (DAT_803dc594 == 4) {
      DAT_803ddfbc = DAT_803ddfbc | uVar4;
    }
    DAT_803ddfb4 = DAT_803ddfb4 & ~uVar4;
    FUN_802526ec(uVar2);
    if ((DAT_803dc588 == 0x20) &&
       (DAT_803dc588 = countLeadingZeros(DAT_803ddfb8), DAT_803dc588 != 0x20)) {
      DAT_803ddfb8 = DAT_803ddfb8 & ~(0x80000000U >> DAT_803dc588);
      FUN_800033a8(&DAT_803ae1c0 + DAT_803dc588 * 0xc,0,0xc);
      FUN_80252f44(DAT_803dc588,&LAB_8024dff0);
    }
    FUN_802437a4(uVar1);
  }
  return 1;
}

