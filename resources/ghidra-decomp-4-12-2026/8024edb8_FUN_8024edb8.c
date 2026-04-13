// Function: FUN_8024edb8
// Entry: 8024edb8
// Size: 528 bytes

undefined4 FUN_8024edb8(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  
  if (DAT_803dec30 == 0) {
    if (DAT_803dec54 != 0) {
      FUN_8024f418(DAT_803dec54);
    }
    DAT_803dec30 = 1;
    if (DAT_803ded08 != 0) {
      uVar4 = FUN_802473b4();
      iVar1 = (int)((ulonglong)uVar4 >> 0x20);
      uVar2 = (uint)uVar4;
      uVar5 = FUN_80286bf4(iVar1,uVar2,0x10);
      uVar6 = FUN_80286bf4(iVar1,uVar2,0x20);
      uVar7 = FUN_80286bf4(iVar1,uVar2,0x30);
      DAT_803dec3c = 0xf0000000;
      DAT_800030e0 = (short)uVar7 + (short)uVar6 + (short)uVar4 + (short)uVar5 & 0x3fff;
    }
    DAT_803aee50 = (DAT_800030e0 & 0x3fff) << 8 | 0x4d000000;
    DAT_803aee54 = (DAT_800030e0 & 0x3fff) << 8 | 0x4d400000;
    DAT_803aee58 = (DAT_800030e0 & 0x3fff) << 8 | 0x4d800000;
    DAT_803aee5c = (DAT_800030e0 & 0x3fff) << 8 | 0x4dc00000;
    FUN_802538c8();
    FUN_80244e64(-0x7fcd12f0);
    FUN_80243e74();
    uVar3 = (DAT_803dec48 | 0xf0000000) & ~(DAT_803dec40 | DAT_803dec44);
    DAT_803dec38 = DAT_803dec38 | uVar3;
    DAT_803dec48 = 0;
    uVar2 = DAT_803dec38 & DAT_803dec34;
    if (DAT_803dd1fc == 4) {
      DAT_803dec3c = DAT_803dec3c | uVar3;
    }
    DAT_803dec34 = DAT_803dec34 & ~uVar3;
    FUN_80252e50(uVar2);
    if ((DAT_803dd1f0 == 0x20) &&
       (DAT_803dd1f0 = countLeadingZeros(DAT_803dec38), DAT_803dd1f0 != 0x20)) {
      DAT_803dec38 = DAT_803dec38 & ~(0x80000000U >> DAT_803dd1f0);
      FUN_800033a8((int)(&DAT_803aee20 + DAT_803dd1f0 * 0xc),0,0xc);
      FUN_802536a8(DAT_803dd1f0,&LAB_8024e754);
    }
    FUN_80243e9c();
  }
  return 1;
}

