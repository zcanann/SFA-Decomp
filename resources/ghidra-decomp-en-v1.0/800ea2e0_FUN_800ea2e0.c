// Function: FUN_800ea2e0
// Entry: 800ea2e0
// Size: 488 bytes

void FUN_800ea2e0(void)

{
  short sVar1;
  uint uVar2;
  undefined *puVar3;
  uint uVar4;
  uint uVar5;
  uint unaff_r27;
  short sVar6;
  uint uVar7;
  short *psVar8;
  
  uVar2 = FUN_802860d0();
  puVar3 = (undefined *)FUN_800e8044();
  sVar6 = -1;
  if (puVar3[6] == '\0') {
    psVar8 = &DAT_803119e2;
    for (uVar7 = 1; (short)uVar7 < 0xce; uVar7 = uVar7 + 1) {
      if ((*psVar8 == 0xffff) || (*psVar8 == -1)) {
        uVar4 = 1 << (uVar7 & 0x1f);
        sVar1 = (short)((uVar7 & 0xff) >> 5) + 0x12f;
        uVar5 = FUN_8001ffb4(sVar1);
        if ((uVar5 & uVar4) == 0) {
          FUN_800200e8(sVar1,uVar5 | uVar4);
        }
      }
      psVar8 = psVar8 + 1;
    }
  }
  uVar5 = 1 << (uVar2 & 0x1f);
  sVar1 = (short)((uVar2 & 0xff) >> 5) + 0x12f;
  uVar7 = FUN_8001ffb4(sVar1);
  if ((uVar7 & uVar5) == 0) {
    FUN_800200e8(sVar1,uVar7 | uVar5);
    if (puVar3[6] != '\x05') {
      puVar3[6] = puVar3[6] + '\x01';
    }
    for (sVar1 = 4; sVar1 != 0; sVar1 = sVar1 + -1) {
      puVar3[sVar1] = puVar3[sVar1 + -1];
    }
    *puVar3 = (char)uVar2;
    if ((uint)(byte)puVar3[5] == (uVar2 & 0xff)) {
      do {
        puVar3[5] = puVar3[5] + '\x01';
        sVar1 = ((byte)puVar3[5] >> 5) + 0x12f;
        if (sVar1 != sVar6) {
          unaff_r27 = FUN_8001ffb4();
          sVar6 = sVar1;
        }
      } while ((unaff_r27 & 1 << ((byte)puVar3[5] & 0x1f)) != 0);
    }
  }
  FUN_8028611c();
  return;
}

