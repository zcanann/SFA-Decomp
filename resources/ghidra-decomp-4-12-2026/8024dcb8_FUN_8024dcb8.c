// Function: FUN_8024dcb8
// Entry: 8024dcb8
// Size: 284 bytes

void FUN_8024dcb8(void)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  
  FUN_80243e74();
  DAT_803dec10 = DAT_803dec10 | DAT_803dec00;
  DAT_803dec00 = 0;
  DAT_803dec18 = DAT_803dec18 | DAT_803dec08;
  DAT_803dec1c = DAT_803dec1c | DAT_803dec0c;
  for (; uVar1 = DAT_803dec0c, DAT_803dec0c != 0 || DAT_803dec08 != 0;
      DAT_803dec0c = DAT_803dec0c & ~(uint)uVar3) {
    uVar3 = FUN_80286bd0(DAT_803dec08,DAT_803dec0c,0x20);
    iVar2 = countLeadingZeros((int)uVar3);
    if (0x1f < iVar2) {
      iVar2 = countLeadingZeros(uVar1);
      iVar2 = iVar2 + 0x20;
    }
    *(undefined2 *)(&DAT_803aed40 + iVar2 * 2) = (&DAT_803aecc8)[iVar2];
    uVar3 = FUN_80286bac(0,1,0x3f - iVar2);
    DAT_803dec08 = DAT_803dec08 & ~(uint)((ulonglong)uVar3 >> 0x20);
  }
  DAT_803debe4 = 1;
  FUN_80243e9c();
  return;
}

