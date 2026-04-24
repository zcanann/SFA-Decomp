// Function: FUN_8007e7c0
// Entry: 8007e7c0
// Size: 900 bytes

int FUN_8007e7c0(uint param_1)

{
  uint uVar1;
  uint uVar2;
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
  int iVar13;
  int iVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint *puVar23;
  uint uVar24;
  bool bVar25;
  
  iVar14 = DAT_803dd044;
  uVar2 = 0;
  uVar1 = 0;
  uVar6 = 1;
  iVar13 = 0;
  for (uVar4 = 0; uVar4 < 0x3f7; uVar4 = uVar4 + 8) {
    puVar23 = (uint *)(DAT_803dd044 + (uint)uVar4 * 8);
    uVar11 = puVar23[1];
    bVar25 = CARRY4(uVar6,uVar11);
    uVar3 = uVar6 + uVar11;
    uVar12 = puVar23[3];
    uVar7 = uVar3 + uVar12;
    uVar15 = puVar23[5];
    uVar5 = uVar7 + uVar15;
    uVar16 = puVar23[7];
    uVar24 = uVar5 + uVar16;
    uVar17 = puVar23[9];
    uVar8 = uVar24 + uVar17;
    uVar18 = puVar23[0xb];
    uVar9 = uVar8 + uVar18;
    uVar19 = puVar23[0xd];
    uVar10 = uVar9 + uVar19;
    uVar20 = puVar23[0xf];
    uVar2 = uVar2 ^ uVar11 ^ uVar12 ^ uVar15 ^ uVar16 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20;
    uVar1 = uVar1 ^ *puVar23 ^ puVar23[2] ^ puVar23[4] ^ puVar23[6] ^ puVar23[8] ^ puVar23[10] ^
            puVar23[0xc] ^ puVar23[0xe];
    uVar6 = uVar10 + uVar20;
    iVar13 = iVar13 + *puVar23 + (uint)bVar25 + puVar23[2] + (uint)CARRY4(uVar3,uVar12) +
             puVar23[4] + (uint)CARRY4(uVar7,uVar15) + puVar23[6] + (uint)CARRY4(uVar5,uVar16) +
             puVar23[8] + (uint)CARRY4(uVar24,uVar17) + puVar23[10] + (uint)CARRY4(uVar8,uVar18) +
             puVar23[0xc] + (uint)CARRY4(uVar9,uVar19) + puVar23[0xe] + (uint)CARRY4(uVar10,uVar20);
  }
  for (; uVar4 < 0x3ff; uVar4 = uVar4 + 1) {
    puVar23 = (uint *)(DAT_803dd044 + (uint)uVar4 * 8);
    uVar3 = *puVar23;
    uVar7 = puVar23[1];
    uVar2 = uVar2 ^ uVar7;
    uVar1 = uVar1 ^ uVar3;
    bVar25 = CARRY4(uVar6,uVar7);
    uVar6 = uVar6 + uVar7;
    iVar13 = iVar13 + uVar3 + bVar25;
  }
  uVar2 = uVar2 ^ uVar6 + 0xd;
  uVar1 = uVar1 ^ iVar13 + (uint)(0xfffffff2 < uVar6);
  *(uint *)(DAT_803dd044 + 0x1ffc) = uVar2;
  *(uint *)(iVar14 + 0x1ff8) = uVar1;
  FUN_802419e8(DAT_803dd044,0x2000);
  iVar14 = (param_1 & 0xff) << 0xd;
  iVar13 = FUN_80263cc4(&DAT_80396900,DAT_803dd044,0x2000,iVar14);
  if (iVar13 == -5) {
    FUN_80263ec0(0,DAT_803db704);
  }
  uVar6 = DAT_803dd050;
  uVar3 = DAT_803dd054;
  if (iVar13 == 0) {
    FUN_802419b8(DAT_803dd044,0x2000);
    iVar13 = FUN_80263948(&DAT_80396900,DAT_803dd044,0x2000,iVar14);
    uVar6 = DAT_803dd050;
    uVar3 = DAT_803dd054;
    if (iVar13 == 0) {
      uVar3 = 0;
      uVar6 = 0;
      uVar7 = 1;
      iVar14 = 0;
      for (uVar4 = 0; uVar4 < 0x3f7; uVar4 = uVar4 + 8) {
        puVar23 = (uint *)(DAT_803dd044 + (uint)uVar4 * 8);
        uVar15 = puVar23[1];
        bVar25 = CARRY4(uVar7,uVar15);
        uVar5 = uVar7 + uVar15;
        uVar16 = puVar23[3];
        uVar24 = uVar5 + uVar16;
        uVar17 = puVar23[5];
        uVar8 = uVar24 + uVar17;
        uVar18 = puVar23[7];
        uVar9 = uVar8 + uVar18;
        uVar19 = puVar23[9];
        uVar10 = uVar9 + uVar19;
        uVar20 = puVar23[0xb];
        uVar11 = uVar10 + uVar20;
        uVar21 = puVar23[0xd];
        uVar12 = uVar11 + uVar21;
        uVar22 = puVar23[0xf];
        uVar3 = uVar3 ^ uVar15 ^ uVar16 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21 ^ uVar22;
        uVar6 = uVar6 ^ *puVar23 ^ puVar23[2] ^ puVar23[4] ^ puVar23[6] ^ puVar23[8] ^ puVar23[10] ^
                puVar23[0xc] ^ puVar23[0xe];
        uVar7 = uVar12 + uVar22;
        iVar14 = iVar14 + *puVar23 + (uint)bVar25 + puVar23[2] + (uint)CARRY4(uVar5,uVar16) +
                 puVar23[4] + (uint)CARRY4(uVar24,uVar17) + puVar23[6] + (uint)CARRY4(uVar8,uVar18)
                 + puVar23[8] + (uint)CARRY4(uVar9,uVar19) +
                 puVar23[10] + (uint)CARRY4(uVar10,uVar20) +
                 puVar23[0xc] + (uint)CARRY4(uVar11,uVar21) +
                 puVar23[0xe] + (uint)CARRY4(uVar12,uVar22);
      }
      for (; uVar4 < 0x3ff; uVar4 = uVar4 + 1) {
        puVar23 = (uint *)(DAT_803dd044 + (uint)uVar4 * 8);
        uVar5 = *puVar23;
        uVar24 = puVar23[1];
        uVar3 = uVar3 ^ uVar24;
        uVar6 = uVar6 ^ uVar5;
        bVar25 = CARRY4(uVar7,uVar24);
        uVar7 = uVar7 + uVar24;
        iVar14 = iVar14 + uVar5 + bVar25;
      }
      uVar3 = uVar3 ^ uVar7 + 0xd;
      uVar6 = uVar6 ^ iVar14 + (uint)(0xfffffff2 < uVar7);
      if ((uVar2 ^ uVar3 | uVar1 ^ uVar6) != 0) {
        iVar13 = -0x55;
        DAT_803db700 = 10;
        uVar6 = DAT_803dd050;
        uVar3 = DAT_803dd054;
      }
    }
  }
  DAT_803dd054 = uVar3;
  DAT_803dd050 = uVar6;
  return iVar13;
}

