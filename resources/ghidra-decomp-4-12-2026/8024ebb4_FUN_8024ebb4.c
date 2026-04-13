// Function: FUN_8024ebb4
// Entry: 8024ebb4
// Size: 256 bytes

undefined4 FUN_8024ebb4(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  FUN_80243e74();
  uVar2 = (param_1 | DAT_803dec48) & ~(DAT_803dec40 | DAT_803dec44);
  DAT_803dec38 = DAT_803dec38 | uVar2;
  DAT_803dec48 = 0;
  uVar1 = DAT_803dec38 & DAT_803dec34;
  if (DAT_803dd1fc == 4) {
    DAT_803dec3c = DAT_803dec3c | uVar2;
  }
  DAT_803dec34 = DAT_803dec34 & ~uVar2;
  FUN_80252e50(uVar1);
  if (DAT_803dd1f0 == 0x20) {
    DAT_803dd1f0 = countLeadingZeros(DAT_803dec38);
    if (DAT_803dd1f0 != 0x20) {
      DAT_803dec38 = DAT_803dec38 & ~(0x80000000U >> DAT_803dd1f0);
      FUN_800033a8((int)(&DAT_803aee20 + DAT_803dd1f0 * 0xc),0,0xc);
      FUN_802536a8(DAT_803dd1f0,&LAB_8024e754);
    }
  }
  FUN_80243e9c();
  return 1;
}

