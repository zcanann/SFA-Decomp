// Function: FUN_8007f2e0
// Entry: 8007f2e0
// Size: 1372 bytes

void FUN_8007f2e0(void)

{
  undefined *puVar1;
  int iVar2;
  uint uVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint *puVar23;
  bool bVar24;
  undefined auStack72 [68];
  
  if (DAT_803dc968 == '\0') {
    FUN_8028f688(DAT_803dd05c,s_Star_Fox_Adventures_8030eab8);
    FUN_8028f688(DAT_803dd05c + 0x20,s_Dinosaur_Planet_8030eb6c);
  }
  else {
    *DAT_803dd05c = 0x83;
    DAT_803dd05c[1] = 0x58;
    DAT_803dd05c[2] = 0x83;
    DAT_803dd05c[3] = 0x5e;
    DAT_803dd05c[4] = 0x81;
    DAT_803dd05c[5] = 0x5b;
    DAT_803dd05c[6] = 0x83;
    DAT_803dd05c[7] = 0x74;
    DAT_803dd05c[8] = 0x83;
    DAT_803dd05c[9] = 0x48;
    DAT_803dd05c[10] = 0x83;
    DAT_803dd05c[0xb] = 0x62;
    DAT_803dd05c[0xc] = 0x83;
    DAT_803dd05c[0xd] = 0x4e;
    DAT_803dd05c[0xe] = 0x83;
    DAT_803dd05c[0xf] = 0x58;
    DAT_803dd05c[0x10] = 0x83;
    DAT_803dd05c[0x11] = 0x41;
    DAT_803dd05c[0x12] = 0x83;
    DAT_803dd05c[0x13] = 0x68;
    DAT_803dd05c[0x14] = 0x83;
    DAT_803dd05c[0x15] = 0x78;
    DAT_803dd05c[0x16] = 0x83;
    DAT_803dd05c[0x17] = 0x93;
    DAT_803dd05c[0x18] = 0x83;
    DAT_803dd05c[0x19] = 0x60;
    DAT_803dd05c[0x1a] = 0x83;
    DAT_803dd05c[0x1b] = 0x83;
    DAT_803dd05c[0x1c] = 0x81;
    DAT_803dd05c[0x1d] = 0x5b;
    DAT_803dd05c[0x1e] = 0;
    DAT_803dd05c[0x1f] = 0;
    FUN_8028f688(DAT_803dd05c + 0x20,s_STARFOX_ADVENTURES_8030eb58);
  }
  iVar2 = FUN_80248b9c(s_opening_bnr_8030eb7c,auStack72);
  if (iVar2 != 0) {
    FUN_80015850(auStack72,DAT_803dd05c + 0x40,0x1800,0x20);
    FUN_80248c64(auStack72);
  }
  iVar2 = FUN_80248b9c(s_card_memcardicon0_img_8030eb88,auStack72);
  if (iVar2 != 0) {
    FUN_80015850(auStack72,DAT_803dd05c + 0x1840,0x400,0);
    FUN_80248c64(auStack72);
  }
  iVar2 = FUN_80248b9c(s_card_memcardicon1_img_8030eba0,auStack72);
  if (iVar2 != 0) {
    FUN_80015850(auStack72,DAT_803dd05c + 0x1c40,0x400,0);
    FUN_80248c64(auStack72);
  }
  iVar2 = FUN_80248b9c(s_card_memcardicon2_img_8030ebb8,auStack72);
  if (iVar2 != 0) {
    FUN_80015850(auStack72,DAT_803dd05c + 0x2040,0x400,0);
    FUN_80248c64(auStack72);
  }
  iVar2 = FUN_80248b9c(s_card_memcardicon3_img_8030ebd0,auStack72);
  if (iVar2 != 0) {
    FUN_80015850(auStack72,DAT_803dd05c + 0x2440,0x400,0);
    FUN_80248c64(auStack72);
  }
  iVar2 = FUN_80248b9c(s_card_memcardicon0_pal_8030ebe8,auStack72);
  if (iVar2 != 0) {
    FUN_80015850(auStack72,DAT_803dd05c + 0x2840,0x200,0);
    FUN_80248c64(auStack72);
  }
  puVar1 = DAT_803dd05c;
  uVar7 = 0;
  uVar6 = 0;
  uVar3 = 1;
  iVar2 = 0;
  for (uVar13 = 0; (uVar13 & 0xffff) < 0x400; uVar13 = uVar13 + 8) {
    puVar23 = (uint *)(DAT_803dd05c + (uVar13 & 0xffff) * 8);
    uVar22 = puVar23[1];
    bVar24 = CARRY4(uVar3,uVar22);
    uVar8 = uVar3 + uVar22;
    uVar17 = puVar23[3];
    uVar9 = uVar8 + uVar17;
    uVar18 = puVar23[5];
    uVar10 = uVar9 + uVar18;
    uVar19 = puVar23[7];
    uVar11 = uVar10 + uVar19;
    uVar20 = puVar23[9];
    uVar12 = uVar11 + uVar20;
    uVar21 = puVar23[0xb];
    uVar14 = uVar12 + uVar21;
    uVar5 = puVar23[0xd];
    uVar15 = uVar14 + uVar5;
    uVar16 = puVar23[0xf];
    uVar7 = uVar7 ^ uVar22 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21 ^ uVar5 ^ uVar16;
    uVar6 = uVar6 ^ *puVar23 ^ puVar23[2] ^ puVar23[4] ^ puVar23[6] ^ puVar23[8] ^ puVar23[10] ^
            puVar23[0xc] ^ puVar23[0xe];
    uVar3 = uVar15 + uVar16;
    iVar2 = iVar2 + *puVar23 + (uint)bVar24 + puVar23[2] + (uint)CARRY4(uVar8,uVar17) +
            puVar23[4] + (uint)CARRY4(uVar9,uVar18) + puVar23[6] + (uint)CARRY4(uVar10,uVar19) +
            puVar23[8] + (uint)CARRY4(uVar11,uVar20) + puVar23[10] + (uint)CARRY4(uVar12,uVar21) +
            puVar23[0xc] + (uint)CARRY4(uVar14,uVar5) + puVar23[0xe] + (uint)CARRY4(uVar15,uVar16);
  }
  uVar13 = 0;
  *(uint *)(DAT_803dd05c + 0x2a44) = uVar7 ^ uVar3 + 0xd;
  *(uint *)(puVar1 + 0x2a40) = uVar6 ^ iVar2 + (uint)(0xfffffff2 < uVar3);
  puVar1 = DAT_803dd05c;
  uVar3 = 0;
  uVar6 = 1;
  iVar2 = 0;
  for (uVar4 = 0; uVar4 < 0x3f7; uVar4 = uVar4 + 8) {
    puVar23 = (uint *)(DAT_803dd05c + (uint)uVar4 * 8 + 0x2000);
    uVar14 = puVar23[1];
    bVar24 = CARRY4(uVar6,uVar14);
    uVar7 = uVar6 + uVar14;
    uVar15 = puVar23[3];
    uVar22 = uVar7 + uVar15;
    uVar16 = puVar23[5];
    uVar8 = uVar22 + uVar16;
    uVar17 = puVar23[7];
    uVar9 = uVar8 + uVar17;
    uVar18 = puVar23[9];
    uVar10 = uVar9 + uVar18;
    uVar19 = puVar23[0xb];
    uVar11 = uVar10 + uVar19;
    uVar20 = puVar23[0xd];
    uVar12 = uVar11 + uVar20;
    uVar21 = puVar23[0xf];
    uVar13 = uVar13 ^ uVar14 ^ uVar15 ^ uVar16 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21;
    uVar3 = uVar3 ^ *puVar23 ^ puVar23[2] ^ puVar23[4] ^ puVar23[6] ^ puVar23[8] ^ puVar23[10] ^
            puVar23[0xc] ^ puVar23[0xe];
    uVar6 = uVar12 + uVar21;
    iVar2 = iVar2 + *puVar23 + (uint)bVar24 + puVar23[2] + (uint)CARRY4(uVar7,uVar15) +
            puVar23[4] + (uint)CARRY4(uVar22,uVar16) + puVar23[6] + (uint)CARRY4(uVar8,uVar17) +
            puVar23[8] + (uint)CARRY4(uVar9,uVar18) + puVar23[10] + (uint)CARRY4(uVar10,uVar19) +
            puVar23[0xc] + (uint)CARRY4(uVar11,uVar20) + puVar23[0xe] + (uint)CARRY4(uVar12,uVar21);
  }
  for (; uVar4 < 0x3ff; uVar4 = uVar4 + 1) {
    uVar7 = *(uint *)(DAT_803dd05c + (uint)uVar4 * 8 + 0x2000);
    uVar22 = *(uint *)((int)(DAT_803dd05c + (uint)uVar4 * 8 + 0x2000) + 4);
    uVar13 = uVar13 ^ uVar22;
    uVar3 = uVar3 ^ uVar7;
    bVar24 = CARRY4(uVar6,uVar22);
    uVar6 = uVar6 + uVar22;
    iVar2 = iVar2 + uVar7 + bVar24;
  }
  *(uint *)(DAT_803dd05c + 0x3ffc) = uVar13 ^ uVar6 + 0xd;
  *(uint *)(puVar1 + 0x3ff8) = uVar3 ^ iVar2 + (uint)(0xfffffff2 < uVar6);
  FUN_802419e8(DAT_803dd05c,0x4000);
  return;
}

