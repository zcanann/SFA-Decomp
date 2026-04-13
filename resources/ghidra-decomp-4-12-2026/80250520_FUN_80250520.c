// Function: FUN_80250520
// Entry: 80250520
// Size: 484 bytes

void FUN_80250520(void)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  longlong lVar9;
  undefined8 uVar10;
  
  lVar9 = 0;
  bVar1 = false;
  uVar7 = 0;
  uVar8 = 0;
  while (!bVar1) {
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 & 0xffffffdf | 0x20;
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 & 0xfffffffd;
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 & 0xfffffffe | 1;
    iVar3 = DAT_cc006c08;
    do {
      iVar4 = DAT_cc006c08;
    } while (iVar3 == iVar4);
    uVar10 = FUN_802473b4();
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 & 0xfffffffd | 2;
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 & 0xfffffffe | 1;
    iVar3 = DAT_cc006c08;
    do {
      iVar4 = DAT_cc006c08;
    } while (iVar3 == iVar4);
    lVar9 = FUN_802473b4();
    uVar6 = (uint)lVar9 - (uint)uVar10;
    uVar2 = DAT_cc006c00;
    uVar5 = (int)((ulonglong)lVar9 >> 0x20) -
            ((uint)((uint)lVar9 < (uint)uVar10) + (int)((ulonglong)uVar10 >> 0x20)) ^ 0x80000000;
    DAT_cc006c00 = uVar2 & 0xfffffffd;
    uVar2 = DAT_cc006c00;
    DAT_cc006c00 = uVar2 & 0xfffffffe;
    if (uVar5 < (uint)(uVar6 < DAT_803dec74 - DAT_803dec94) +
                (DAT_803dec70 - ((uint)(DAT_803dec74 < DAT_803dec94) + DAT_803dec90) ^ 0x80000000))
    {
      bVar1 = true;
      uVar7 = DAT_803dec84;
      uVar8 = DAT_803dec80;
    }
    else if ((uVar5 < (uint)(uVar6 < DAT_803dec74 + DAT_803dec94) +
                      (DAT_803dec70 + DAT_803dec90 + (uint)CARRY4(DAT_803dec74,DAT_803dec94) ^
                      0x80000000)) ||
            ((uint)(uVar6 < DAT_803dec7c - DAT_803dec94) +
             (DAT_803dec78 - ((uint)(DAT_803dec7c < DAT_803dec94) + DAT_803dec90) ^ 0x80000000) <=
             uVar5)) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
      uVar7 = DAT_803dec8c;
      uVar8 = DAT_803dec88;
    }
  }
  lVar9 = lVar9 + CONCAT44(uVar8,uVar7);
  do {
    uVar10 = FUN_802473b4();
  } while (((uint)((ulonglong)uVar10 >> 0x20) ^ 0x80000000) <
           (uint)((uint)uVar10 < (uint)lVar9) + ((uint)((ulonglong)lVar9 >> 0x20) ^ 0x80000000));
  return;
}

