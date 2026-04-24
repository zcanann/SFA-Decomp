// Function: FUN_80081cf8
// Entry: 80081cf8
// Size: 952 bytes

void FUN_80081cf8(void)

{
  short sVar1;
  short sVar2;
  bool bVar3;
  undefined uVar4;
  float fVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  undefined *puVar10;
  char *pcVar11;
  short *psVar12;
  short *psVar13;
  char *pcVar14;
  float *pfVar15;
  float *pfVar16;
  char *pcVar17;
  int *piVar18;
  undefined4 *puVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  int iVar23;
  short *psVar24;
  short *psVar25;
  int iVar26;
  int iVar27;
  uint uVar28;
  undefined auStack424 [4];
  int local_1a4;
  short local_1a0 [90];
  int local_ec [59];
  
  FUN_802860b0();
  piVar7 = (int *)FUN_8002e0fc(auStack424,&local_1a4);
  fVar5 = FLOAT_803deff0;
  uVar4 = DAT_803db410;
  if (DAT_803dd060 != DAT_803dd062) {
    DAT_803dd062 = DAT_803dd060;
  }
  puVar10 = &DAT_8039a300;
  pcVar11 = &DAT_8039a50c;
  pcVar14 = &DAT_8039a564;
  pfVar15 = (float *)&DAT_8039a058;
  pfVar16 = (float *)&DAT_8039a1ac;
  pcVar17 = &DAT_80399ca4;
  iVar27 = 0x55;
  do {
    *puVar10 = 0;
    if ((*pcVar11 != '\0') && (*pcVar14 == '\0')) {
      *puVar10 = uVar4;
    }
    *pcVar14 = *pcVar11;
    *pcVar11 = '\0';
    *pfVar16 = *pfVar15;
    *pfVar15 = fVar5;
    if (*pcVar17 == '\x02') {
      *pcVar17 = '\x01';
    }
    else {
      *pcVar17 = '\0';
    }
    puVar10 = puVar10 + 1;
    pcVar11 = pcVar11 + 1;
    pcVar14 = pcVar14 + 1;
    pfVar15 = pfVar15 + 1;
    pfVar16 = pfVar16 + 1;
    pcVar17 = pcVar17 + 1;
    iVar27 = iVar27 + -1;
  } while (iVar27 != 0);
  iVar26 = (int)DAT_803dd0bc;
  psVar24 = local_1a0;
  psVar12 = psVar24;
  psVar13 = &DAT_80399398 + iVar26 * 3;
  iVar27 = 0;
  while (0 < iVar26) {
    psVar25 = psVar13 + -3;
    iVar26 = iVar26 + -1;
    sVar1 = *psVar25;
    iVar22 = (int)sVar1;
    sVar2 = psVar13[-2];
    (&DAT_8039a45c)[iVar22] = 0;
    (&DAT_8039a4b4)[iVar22] = 0;
    (&DAT_8039a358)[iVar22] = 0;
    bVar3 = true;
    piVar18 = piVar7;
    iVar6 = 0;
    for (iVar23 = 0; iVar23 < local_1a4; iVar23 = iVar23 + 1) {
      iVar9 = *piVar18;
      iVar21 = iVar6;
      if (*(short *)(iVar9 + 0x44) == 0x10) {
        iVar20 = *(int *)(iVar9 + 0x4c);
        puVar19 = *(undefined4 **)(iVar9 + 0xb8);
        if ((iVar20 != 0) && (*(char *)(iVar20 + 0x1f) == iVar22)) {
          if ((*(short *)(iVar20 + 0x1c) < 4) || (iVar8 = FUN_80081bf0(iVar9), iVar8 != 0)) {
            *puVar19 = 0;
          }
          else {
            bVar3 = false;
            FUN_80137948(s__SEQUENCE__Could_not_Find_Object_8030ef00,*(short *)(iVar20 + 0x1c) + -4)
            ;
          }
          if (iVar6 < 0x28) {
            iVar21 = iVar6 + 1;
            local_ec[iVar6] = iVar9;
          }
        }
      }
      piVar18 = piVar18 + 1;
      iVar6 = iVar21;
    }
    piVar18 = local_ec;
    for (iVar23 = 0; iVar23 < iVar6; iVar23 = iVar23 + 1) {
      iVar21 = *piVar18;
      if ((*(int *)(iVar21 + 0x4c) != 0) && (*(char *)(*(int *)(iVar21 + 0x4c) + 0x1f) == iVar22)) {
        iVar9 = *(int *)(iVar21 + 0xb8);
        if (bVar3) {
          *(undefined *)(iVar9 + 0x7e) = 2;
          *(short *)(iVar9 + 0x5e) = sVar2;
          FUN_80087380((double)FLOAT_803defc8,iVar21);
          FUN_8000e10c(iVar21,iVar21 + 0x18,iVar21 + 0x1c,iVar21 + 0x20);
        }
        else {
          *(undefined *)(iVar9 + 0x7e) = 3;
        }
      }
      piVar18 = piVar18 + 1;
    }
    psVar13 = psVar25;
    if (!bVar3) {
      *psVar12 = sVar1;
      psVar12 = psVar12 + 3;
      local_1a0[iVar27 * 3 + 1] = sVar2;
      iVar27 = iVar27 + 1;
    }
  }
  iVar26 = 0;
  if (0 < iVar27) {
    if (8 < iVar27) {
      psVar12 = &DAT_80399398;
      uVar28 = iVar27 - 1U >> 3;
      if (0 < iVar27 + -8) {
        do {
          *psVar12 = *psVar24;
          psVar12[1] = psVar24[1];
          psVar12[3] = psVar24[3];
          psVar12[4] = psVar24[4];
          psVar12[6] = psVar24[6];
          psVar12[7] = psVar24[7];
          psVar12[9] = psVar24[9];
          psVar12[10] = psVar24[10];
          psVar12[0xc] = psVar24[0xc];
          psVar12[0xd] = psVar24[0xd];
          psVar12[0xf] = psVar24[0xf];
          psVar12[0x10] = psVar24[0x10];
          psVar12[0x12] = psVar24[0x12];
          psVar12[0x13] = psVar24[0x13];
          psVar12[0x15] = psVar24[0x15];
          psVar12[0x16] = psVar24[0x16];
          psVar24 = psVar24 + 0x18;
          psVar12 = psVar12 + 0x18;
          iVar26 = iVar26 + 8;
          uVar28 = uVar28 - 1;
        } while (uVar28 != 0);
      }
    }
    psVar12 = local_1a0 + iVar26 * 3;
    psVar13 = &DAT_80399398 + iVar26 * 3;
    iVar6 = iVar27 - iVar26;
    if (iVar26 < iVar27) {
      do {
        *psVar13 = *psVar12;
        psVar13[1] = psVar12[1];
        psVar12 = psVar12 + 3;
        psVar13 = psVar13 + 3;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
  }
  DAT_803dd0bc = (char)iVar27;
  FUN_802860fc();
  return;
}

