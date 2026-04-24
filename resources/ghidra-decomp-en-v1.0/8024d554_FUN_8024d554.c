// Function: FUN_8024d554
// Entry: 8024d554
// Size: 284 bytes

void FUN_8024d554(void)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 extraout_r4;
  int iVar3;
  undefined8 uVar4;
  
  uVar2 = FUN_8024377c();
  DAT_803ddf90 = DAT_803ddf90 | DAT_803ddf80;
  DAT_803ddf80 = 0;
  DAT_803ddf98 = DAT_803ddf98 | DAT_803ddf88;
  DAT_803ddf9c = DAT_803ddf9c | DAT_803ddf8c;
  for (; uVar1 = DAT_803ddf8c, (DAT_803ddf8c | DAT_803ddf88) != 0;
      DAT_803ddf8c = DAT_803ddf8c & ~(uint)uVar4) {
    FUN_8028646c(DAT_803ddf88,DAT_803ddf8c,0x20);
    iVar3 = countLeadingZeros(extraout_r4);
    if (0x1f < iVar3) {
      iVar3 = countLeadingZeros(uVar1);
      iVar3 = iVar3 + 0x20;
    }
    *(undefined2 *)(&DAT_803ae0e0 + iVar3 * 2) = (&DAT_803ae068)[iVar3];
    uVar4 = FUN_80286448(0,1,0x3f - iVar3);
    DAT_803ddf88 = DAT_803ddf88 & ~(uint)((ulonglong)uVar4 >> 0x20);
  }
  DAT_803ddf64 = 1;
  FUN_802437a4(uVar2);
  return;
}

