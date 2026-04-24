// Function: FUN_800ea564
// Entry: 800ea564
// Size: 488 bytes

void FUN_800ea564(void)

{
  uint uVar1;
  undefined *puVar2;
  short sVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint unaff_r27;
  uint uVar7;
  uint uVar8;
  short *psVar9;
  
  uVar1 = FUN_80286834();
  puVar2 = FUN_800e82c8();
  uVar7 = 0xffffffff;
  if (puVar2[6] == '\0') {
    psVar9 = &DAT_80312632;
    for (uVar8 = 1; (short)uVar8 < 0xce; uVar8 = uVar8 + 1) {
      if ((*psVar9 == 0xffff) || (*psVar9 == -1)) {
        uVar5 = 1 << (uVar8 & 0x1f);
        uVar6 = (uint)(short)((short)((uVar8 & 0xff) >> 5) + 0x12f);
        uVar4 = FUN_80020078(uVar6);
        if ((uVar4 & uVar5) == 0) {
          FUN_800201ac(uVar6,uVar4 | uVar5);
        }
      }
      psVar9 = psVar9 + 1;
    }
  }
  uVar6 = 1 << (uVar1 & 0x1f);
  uVar4 = (uint)(short)((short)((uVar1 & 0xff) >> 5) + 0x12f);
  uVar8 = FUN_80020078(uVar4);
  if ((uVar8 & uVar6) == 0) {
    FUN_800201ac(uVar4,uVar8 | uVar6);
    if (puVar2[6] != '\x05') {
      puVar2[6] = puVar2[6] + '\x01';
    }
    for (sVar3 = 4; sVar3 != 0; sVar3 = sVar3 + -1) {
      puVar2[sVar3] = puVar2[sVar3 + -1];
    }
    *puVar2 = (char)uVar1;
    if ((uint)(byte)puVar2[5] == (uVar1 & 0xff)) {
      do {
        puVar2[5] = puVar2[5] + '\x01';
        uVar1 = (uint)(short)(((byte)puVar2[5] >> 5) + 0x12f);
        if (uVar1 != (int)(short)uVar7) {
          unaff_r27 = FUN_80020078(uVar1);
          uVar7 = uVar1;
        }
      } while ((unaff_r27 & 1 << ((byte)puVar2[5] & 0x1f)) != 0);
    }
  }
  FUN_80286880();
  return;
}

