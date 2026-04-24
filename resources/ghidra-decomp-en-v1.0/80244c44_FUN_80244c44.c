// Function: FUN_80244c44
// Entry: 80244c44
// Size: 664 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint FUN_80244c44(void)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  uint extraout_r4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined8 uVar9;
  
  uVar2 = FUN_8024377c();
  _DAT_803dde78 = FUN_80246c70();
  uVar3 = (uint)((ulonglong)_DAT_803dde78 >> 0x20);
  uVar4 = (uint)_DAT_803dde78;
  uVar8 = read_volatile_4(DAT_cc003000);
  if ((uVar8 & 0x10000) == 0) {
    if (DAT_803dde6c == 0) {
      DAT_803dde6c = 1;
      uVar8 = (uint)((DAT_803dde7c | DAT_803dde78) != 0);
      _DAT_803dde80 = _DAT_803dde78;
      _DAT_803dde78 = CONCAT44(DAT_803dde78,DAT_803dde7c);
    }
    else {
      bVar1 = 1;
      if (((DAT_803dde7c | DAT_803dde78) == 0) &&
         ((uint)(((DAT_800000f8 >> 2) / 0x1e848) * 100 >> 3 < uVar4 - DAT_803dde84) +
          (uVar3 - ((uint)(uVar4 < DAT_803dde84) + DAT_803dde80) ^ 0x80000000) < 0x80000001)) {
        bVar1 = 0;
      }
      uVar8 = (uint)bVar1;
      _DAT_803dde80 = CONCAT44(DAT_803dde80,DAT_803dde84);
      _DAT_803dde78 = CONCAT44(DAT_803dde78,DAT_803dde7c);
    }
  }
  else if (DAT_803dde6c == 0) {
    if (((DAT_803dde7c | DAT_803dde78) == 0) ||
       ((uVar4 - DAT_803dde7c < ((DAT_800000f8 >> 2) / 1000) * 0x28) + 0x80000000 <=
        (uVar3 - ((uVar4 < DAT_803dde7c) + DAT_803dde78) ^ 0x80000000))) {
      _DAT_803dde78 = 0;
      uVar8 = 0;
      _DAT_803dde80 = CONCAT44(DAT_803dde80,DAT_803dde84);
    }
    else {
      uVar8 = 1;
      _DAT_803dde80 = CONCAT44(DAT_803dde80,DAT_803dde84);
      _DAT_803dde78 = CONCAT44(DAT_803dde78,DAT_803dde7c);
    }
  }
  else {
    DAT_803dde6c = 0;
    uVar8 = DAT_803dde70;
    if (DAT_803dde70 == 0) {
      _DAT_803dde80 = CONCAT44(DAT_803dde80,DAT_803dde84);
      _DAT_803dde78 = 0;
    }
  }
  DAT_803dde70 = uVar8;
  if ((DAT_800030e3 & 0x3f) != 0) {
    uVar7 = (DAT_800030e3 & 0x3f) * 0x3c;
    uVar5 = uVar7 * (DAT_800000f8 >> 2);
    uVar6 = DAT_803dde04 + uVar5;
    uVar5 = DAT_803dde00 +
            (int)((ulonglong)uVar7 * (ulonglong)(DAT_800000f8 >> 2) >> 0x20) +
            (uint)CARRY4(DAT_803dde04,uVar5);
    if ((uVar5 ^ 0x80000000) < (uint)(uVar6 < uVar4) + (uVar3 ^ 0x80000000)) {
      uVar9 = FUN_8028622c(uVar3 - ((uVar4 < uVar6) + uVar5),uVar4 - uVar6,0);
      FUN_8028622c((int)((ulonglong)uVar9 >> 0x20),(int)uVar9,0,2);
      if ((extraout_r4 & 1) == 0) {
        uVar8 = 1;
      }
      else {
        uVar8 = 0;
      }
    }
  }
  FUN_802437a4(uVar2);
  return uVar8;
}

