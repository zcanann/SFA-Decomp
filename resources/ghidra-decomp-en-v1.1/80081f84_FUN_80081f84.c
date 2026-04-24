// Function: FUN_80081f84
// Entry: 80081f84
// Size: 952 bytes

void FUN_80081f84(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  short sVar2;
  bool bVar3;
  undefined uVar4;
  float fVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  undefined *puVar9;
  char *pcVar10;
  short *psVar11;
  short *psVar12;
  char *pcVar13;
  float *pfVar14;
  float *pfVar15;
  char *pcVar16;
  int *piVar17;
  undefined4 *puVar18;
  int iVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  short *psVar23;
  short *psVar24;
  int iVar25;
  int iVar26;
  uint uVar27;
  undefined4 uStack_1a8;
  int local_1a4;
  short local_1a0 [90];
  int local_ec [59];
  
  FUN_80286814();
  piVar7 = (int *)FUN_8002e1f4(&uStack_1a8,&local_1a4);
  fVar5 = FLOAT_803dfc70;
  uVar4 = DAT_803dc070;
  if (DAT_803ddce0 != DAT_803ddce2) {
    DAT_803ddce2 = DAT_803ddce0;
  }
  puVar9 = &DAT_8039af60;
  pcVar10 = &DAT_8039b16c;
  pcVar13 = &DAT_8039b1c4;
  pfVar14 = (float *)&DAT_8039acb8;
  pfVar15 = (float *)&DAT_8039ae0c;
  pcVar16 = &DAT_8039a904;
  iVar26 = 0x55;
  do {
    *puVar9 = 0;
    if ((*pcVar10 != '\0') && (*pcVar13 == '\0')) {
      *puVar9 = uVar4;
    }
    *pcVar13 = *pcVar10;
    *pcVar10 = '\0';
    *pfVar15 = *pfVar14;
    *pfVar14 = fVar5;
    if (*pcVar16 == '\x02') {
      *pcVar16 = '\x01';
    }
    else {
      *pcVar16 = '\0';
    }
    puVar9 = puVar9 + 1;
    pcVar10 = pcVar10 + 1;
    pcVar13 = pcVar13 + 1;
    pfVar14 = pfVar14 + 1;
    pfVar15 = pfVar15 + 1;
    pcVar16 = pcVar16 + 1;
    iVar26 = iVar26 + -1;
  } while (iVar26 != 0);
  iVar25 = (int)DAT_803ddd3c;
  psVar23 = local_1a0;
  psVar11 = psVar23;
  psVar12 = &DAT_80399ff8 + iVar25 * 3;
  iVar26 = 0;
  while (0 < iVar25) {
    psVar24 = psVar12 + -3;
    iVar25 = iVar25 + -1;
    sVar1 = *psVar24;
    iVar21 = (int)sVar1;
    sVar2 = psVar12[-2];
    (&DAT_8039b0bc)[iVar21] = 0;
    (&DAT_8039b114)[iVar21] = 0;
    (&DAT_8039afb8)[iVar21] = 0;
    bVar3 = true;
    piVar17 = piVar7;
    iVar6 = 0;
    for (iVar22 = 0; iVar22 < local_1a4; iVar22 = iVar22 + 1) {
      iVar8 = *piVar17;
      iVar20 = iVar6;
      if (*(short *)(iVar8 + 0x44) == 0x10) {
        iVar19 = *(int *)(iVar8 + 0x4c);
        puVar18 = *(undefined4 **)(iVar8 + 0xb8);
        if ((iVar19 != 0) && (*(char *)(iVar19 + 0x1f) == iVar21)) {
          if ((*(short *)(iVar19 + 0x1c) < 4) || (iVar19 = FUN_80081e7c(iVar8), iVar19 != 0)) {
            *puVar18 = 0;
          }
          else {
            bVar3 = false;
            FUN_80137cd0();
          }
          if (iVar6 < 0x28) {
            iVar20 = iVar6 + 1;
            local_ec[iVar6] = iVar8;
          }
        }
      }
      piVar17 = piVar17 + 1;
      iVar6 = iVar20;
    }
    piVar17 = local_ec;
    for (iVar22 = 0; iVar22 < iVar6; iVar22 = iVar22 + 1) {
      iVar20 = *piVar17;
      if ((*(int *)(iVar20 + 0x4c) != 0) && (*(char *)(*(int *)(iVar20 + 0x4c) + 0x1f) == iVar21)) {
        iVar8 = *(int *)(iVar20 + 0xb8);
        if (bVar3) {
          *(undefined *)(iVar8 + 0x7e) = 2;
          *(short *)(iVar8 + 0x5e) = sVar2;
          FUN_8008760c((double)FLOAT_803dfc48,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8);
          FUN_8000e12c(iVar20,(float *)(iVar20 + 0x18),(float *)(iVar20 + 0x1c),
                       (float *)(iVar20 + 0x20));
        }
        else {
          *(undefined *)(iVar8 + 0x7e) = 3;
        }
      }
      piVar17 = piVar17 + 1;
    }
    psVar12 = psVar24;
    if (!bVar3) {
      *psVar11 = sVar1;
      psVar11 = psVar11 + 3;
      local_1a0[iVar26 * 3 + 1] = sVar2;
      iVar26 = iVar26 + 1;
    }
  }
  iVar25 = 0;
  if (0 < iVar26) {
    if (8 < iVar26) {
      psVar11 = &DAT_80399ff8;
      uVar27 = iVar26 - 1U >> 3;
      if (0 < iVar26 + -8) {
        do {
          *psVar11 = *psVar23;
          psVar11[1] = psVar23[1];
          psVar11[3] = psVar23[3];
          psVar11[4] = psVar23[4];
          psVar11[6] = psVar23[6];
          psVar11[7] = psVar23[7];
          psVar11[9] = psVar23[9];
          psVar11[10] = psVar23[10];
          psVar11[0xc] = psVar23[0xc];
          psVar11[0xd] = psVar23[0xd];
          psVar11[0xf] = psVar23[0xf];
          psVar11[0x10] = psVar23[0x10];
          psVar11[0x12] = psVar23[0x12];
          psVar11[0x13] = psVar23[0x13];
          psVar11[0x15] = psVar23[0x15];
          psVar11[0x16] = psVar23[0x16];
          psVar23 = psVar23 + 0x18;
          psVar11 = psVar11 + 0x18;
          iVar25 = iVar25 + 8;
          uVar27 = uVar27 - 1;
        } while (uVar27 != 0);
      }
    }
    psVar11 = local_1a0 + iVar25 * 3;
    psVar12 = &DAT_80399ff8 + iVar25 * 3;
    iVar6 = iVar26 - iVar25;
    if (iVar25 < iVar26) {
      do {
        *psVar12 = *psVar11;
        psVar12[1] = psVar11[1];
        psVar11 = psVar11 + 3;
        psVar12 = psVar12 + 3;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
  }
  DAT_803ddd3c = (char)iVar26;
  FUN_80286860();
  return;
}

