// Function: FUN_8024533c
// Entry: 8024533c
// Size: 664 bytes

uint FUN_8024533c(void)

{
  uint uVar1;
  byte bVar2;
  longlong lVar3;
  longlong lVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  longlong lVar11;
  undefined8 uVar12;
  ulonglong uVar13;
  
  FUN_80243e74();
  lVar11 = FUN_802473d4();
  lVar4 = CONCAT44(DAT_803deb00,DAT_803deb04);
  uVar5 = (uint)((ulonglong)lVar11 >> 0x20);
  uVar6 = (uint)lVar11;
  uVar10 = DAT_cc003000;
  if ((uVar10 & 0x10000) == 0) {
    if (DAT_803deaec == 0) {
      DAT_803deaec = 1;
      uVar10 = (uint)(DAT_803deafc != 0 || DAT_803deaf8 != 0);
      lVar3 = CONCAT44(DAT_803deaf8,DAT_803deafc);
      lVar4 = lVar11;
    }
    else {
      bVar2 = 1;
      if ((DAT_803deafc == 0 && DAT_803deaf8 == 0) &&
         ((uint)((DAT_800000f8 / 500000) * 100 >> 3 < uVar6 - DAT_803deb04) +
          (uVar5 - ((uint)(uVar6 < DAT_803deb04) + DAT_803deb00) ^ 0x80000000) < 0x80000001)) {
        bVar2 = 0;
      }
      uVar10 = (uint)bVar2;
      lVar3 = CONCAT44(DAT_803deaf8,DAT_803deafc);
      lVar4 = CONCAT44(DAT_803deb00,DAT_803deb04);
    }
  }
  else if (DAT_803deaec == 0) {
    if ((DAT_803deafc == 0 && DAT_803deaf8 == 0) ||
       ((uVar6 - DAT_803deafc < (DAT_800000f8 / 4000) * 0x28) + 0x80000000 <=
        (uVar5 - ((uint)(uVar6 < DAT_803deafc) + DAT_803deaf8) ^ 0x80000000))) {
      uVar10 = 0;
      lVar3 = 0;
      lVar4 = CONCAT44(DAT_803deb00,DAT_803deb04);
    }
    else {
      uVar10 = 1;
      lVar3 = CONCAT44(DAT_803deaf8,DAT_803deafc);
      lVar4 = CONCAT44(DAT_803deb00,DAT_803deb04);
    }
  }
  else {
    DAT_803deaec = 0;
    uVar10 = DAT_803deaf0;
    lVar3 = lVar11;
    if (DAT_803deaf0 == 0) {
      lVar3 = 0;
      lVar4 = CONCAT44(DAT_803deb00,DAT_803deb04);
    }
  }
  DAT_803deb00 = (int)((ulonglong)lVar4 >> 0x20);
  DAT_803deb04 = (uint)lVar4;
  DAT_803deaf8 = (int)((ulonglong)lVar3 >> 0x20);
  DAT_803deafc = (uint)lVar3;
  DAT_803deaf0 = uVar10;
  if ((DAT_800030e3 & 0x3f) != 0) {
    uVar9 = (DAT_800030e3 & 0x3f) * 0x3c;
    uVar1 = DAT_800000f8 >> 2;
    uVar7 = uVar9 * uVar1;
    uVar8 = DAT_803dea84 + uVar7;
    uVar7 = DAT_803dea80 +
            (int)((ulonglong)uVar9 * (ulonglong)uVar1 >> 0x20) + (uint)CARRY4(DAT_803dea84,uVar7);
    if ((uVar7 ^ 0x80000000) < (uint)(uVar8 < uVar6) + (uVar5 ^ 0x80000000)) {
      uVar12 = FUN_80286990(uVar5 - ((uVar6 < uVar8) + uVar7),uVar6 - uVar8,0,uVar1);
      uVar13 = FUN_80286990((uint)((ulonglong)uVar12 >> 0x20),(uint)uVar12,0,2);
      lVar4 = CONCAT44(DAT_803deb00,DAT_803deb04);
      lVar3 = CONCAT44(DAT_803deaf8,DAT_803deafc);
      if ((uVar13 & 1) == 0) {
        uVar10 = 1;
        lVar3 = CONCAT44(DAT_803deaf8,DAT_803deafc);
        lVar4 = CONCAT44(DAT_803deb00,DAT_803deb04);
      }
      else {
        uVar10 = 0;
      }
    }
  }
  DAT_803deb00 = (int)((ulonglong)lVar4 >> 0x20);
  DAT_803deb04 = (uint)lVar4;
  DAT_803deaf8 = (int)((ulonglong)lVar3 >> 0x20);
  DAT_803deafc = (uint)lVar3;
  FUN_80243e9c();
  return uVar10;
}

