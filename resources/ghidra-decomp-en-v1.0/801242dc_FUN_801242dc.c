// Function: FUN_801242dc
// Entry: 801242dc
// Size: 1208 bytes

void FUN_801242dc(void)

{
  uint uVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  char extraout_r4;
  short *psVar6;
  short *psVar7;
  undefined1 *puVar8;
  short *psVar9;
  undefined *puVar10;
  undefined1 *puVar11;
  uint uVar12;
  int iVar13;
  short *psVar14;
  short *psVar15;
  int *piVar16;
  int *piVar17;
  undefined1 *puVar18;
  short *psVar19;
  int iVar20;
  int iVar21;
  short local_a8 [84];
  
  psVar3 = (short *)FUN_802860c8();
  psVar19 = &DAT_803a9138;
  psVar14 = local_a8;
  psVar15 = &DAT_803a8d38;
  puVar18 = &DAT_803a8c38;
  iVar21 = 8;
  psVar6 = psVar19;
  psVar7 = psVar14;
  psVar9 = psVar15;
  puVar11 = puVar18;
  do {
    *psVar7 = *psVar6;
    *psVar6 = -1;
    iVar13 = 0;
    *psVar9 = 0;
    *puVar11 = 1;
    psVar7[1] = psVar6[1];
    psVar6[1] = -1;
    psVar9[1] = 0;
    puVar11[1] = 1;
    psVar7[2] = psVar6[2];
    psVar6[2] = -1;
    psVar9[2] = 0;
    puVar11[2] = 1;
    psVar7[3] = psVar6[3];
    psVar6[3] = -1;
    psVar9[3] = 0;
    puVar11[3] = 1;
    psVar7[4] = psVar6[4];
    psVar6[4] = -1;
    psVar9[4] = 0;
    puVar11[4] = 1;
    psVar7[5] = psVar6[5];
    psVar6[5] = -1;
    psVar9[5] = 0;
    puVar11[5] = 1;
    psVar7[6] = psVar6[6];
    psVar6[6] = -1;
    psVar9[6] = 0;
    puVar11[6] = 1;
    psVar7[7] = psVar6[7];
    psVar6[7] = -1;
    psVar9[7] = 0;
    puVar11[7] = 1;
    psVar6 = psVar6 + 8;
    psVar7 = psVar7 + 8;
    psVar9 = psVar9 + 8;
    puVar11 = puVar11 + 8;
    iVar21 = iVar21 + -1;
  } while (iVar21 != 0);
  iVar20 = 0;
  iVar21 = 0;
  piVar17 = &DAT_803a9038;
  DAT_803a9038 = 0xffffffff;
  if (extraout_r4 == '\0') {
    DAT_803dd894 = 0xffff;
    for (psVar6 = psVar3; -1 < *psVar6; psVar6 = psVar6 + 8) {
      iVar4 = FUN_8001ffb4();
      if (iVar4 != 0) {
        if (psVar3 == &DAT_8031b4e0) {
          if ((psVar6[1] < 0) || (iVar5 = FUN_8001ffb4(), iVar5 == 0)) {
            *(short *)((int)&DAT_803a9138 + iVar13) = psVar6[3];
            *(int *)((int)&DAT_803a9038 + iVar21) = (int)*psVar6;
            *(int *)((int)&DAT_803a8f38 + iVar21) = (int)psVar6[2];
            *(int *)((int)&DAT_803a8e38 + iVar21) = (int)psVar6[1];
            (&DAT_803a8c38)[iVar20] = (char)iVar4;
            *(short *)((int)&DAT_803a8d38 + iVar13) = psVar6[6];
            *(short *)((int)&DAT_803a8db8 + iVar13) = psVar6[5];
            (&DAT_803a8cf8)[iVar20] = *(undefined *)(psVar6 + 7);
            (&DAT_803a8cb8)[iVar20] = *(undefined *)((int)psVar6 + 0xf);
            if ((psVar6[2] < 0) || (iVar4 = FUN_8001ffb4(), iVar4 == 0)) {
              (&DAT_803a8c78)[iVar20] = 1;
            }
            else {
              (&DAT_803a8c78)[iVar20] = 0;
            }
            iVar20 = iVar20 + 1;
            iVar21 = iVar21 + 4;
            iVar13 = iVar13 + 2;
          }
        }
        else if ((psVar6[1] < 0) || (iVar5 = FUN_8001ffb4(), iVar5 == 0)) {
          if ((DAT_803dd896 != 0) && ((int)DAT_803dd896 == (int)*psVar6)) {
            DAT_803dd894 = (undefined2)iVar20;
          }
          *(short *)((int)&DAT_803a9138 + iVar13) = psVar6[3];
          *(int *)((int)&DAT_803a9038 + iVar21) = (int)*psVar6;
          *(int *)((int)&DAT_803a8f38 + iVar21) = (int)psVar6[2];
          *(int *)((int)&DAT_803a8e38 + iVar21) = (int)psVar6[1];
          (&DAT_803a8c38)[iVar20] = (char)iVar4;
          *(short *)((int)&DAT_803a8d38 + iVar13) = psVar6[6];
          *(short *)((int)&DAT_803a8db8 + iVar13) = psVar6[5];
          (&DAT_803a8cf8)[iVar20] = *(undefined *)(psVar6 + 7);
          (&DAT_803a8cb8)[iVar20] = *(undefined *)((int)psVar6 + 0xf);
          if ((psVar6[2] < 0) || (iVar4 = FUN_8001ffb4(), iVar4 == 0)) {
            (&DAT_803a8c78)[iVar20] = 1;
          }
          else {
            (&DAT_803a8c78)[iVar20] = 0;
          }
          iVar20 = iVar20 + 1;
          iVar21 = iVar21 + 4;
          iVar13 = iVar13 + 2;
        }
      }
    }
  }
  else {
    FUN_8002b9ac();
    uVar2 = DAT_803dd73c;
    uVar1 = DAT_803dd738;
    if (DAT_803dd738 == 0xffffffff) {
      if (DAT_803dd884 == 2) {
        DAT_803dd884 = 0;
        DAT_803dd874 = 0xffff;
      }
    }
    else {
      psVar7 = &DAT_803a8db8;
      puVar11 = &DAT_803a8cf8;
      puVar8 = &DAT_803a8cb8;
      puVar10 = &DAT_803a8c78;
      uVar12 = (uint)DAT_803dd88a;
      psVar6 = psVar19;
      for (; -1 < *psVar3; psVar3 = psVar3 + 8) {
        if ((uVar2 & (int)*psVar3) == 0) {
          if ((DAT_803dd884 == 2) && (uVar12 == (int)psVar3[2])) {
            DAT_803dd884 = 0;
            DAT_803dd874 = 0xffff;
          }
        }
        else {
          *psVar6 = psVar3[3];
          *puVar18 = 1;
          *piVar17 = (int)psVar3[2];
          *psVar15 = psVar3[6];
          *psVar7 = psVar3[5];
          *puVar11 = *(undefined *)(psVar3 + 7);
          *puVar8 = *(undefined *)((int)psVar3 + 0xf);
          if ((uVar1 & (int)*psVar3) == 0) {
            *puVar10 = 0;
          }
          else {
            *puVar10 = 1;
          }
          psVar6 = psVar6 + 1;
          puVar18 = puVar18 + 1;
          piVar17 = piVar17 + 1;
          psVar15 = psVar15 + 1;
          psVar7 = psVar7 + 1;
          puVar11 = puVar11 + 1;
          puVar8 = puVar8 + 1;
          puVar10 = puVar10 + 1;
          iVar20 = iVar20 + 1;
        }
      }
    }
  }
  iVar21 = 0;
  piVar16 = &DAT_803a91b8;
  psVar6 = psVar19;
  piVar17 = piVar16;
  do {
    if (((-1 < *psVar14) && (*psVar14 != *psVar6)) && (*piVar17 != 0)) {
      FUN_80054308();
      *piVar17 = 0;
    }
    psVar14 = psVar14 + 1;
    psVar6 = psVar6 + 1;
    piVar17 = piVar17 + 1;
    iVar21 = iVar21 + 1;
  } while (iVar21 < 0x40);
  iVar21 = FUN_800430ac(0);
  if (iVar21 == 0) {
    iVar21 = 0;
    do {
      if ((-1 < *psVar19) && (*piVar16 == 0)) {
        iVar13 = FUN_80054d54();
        *piVar16 = iVar13;
      }
      psVar19 = psVar19 + 1;
      piVar16 = piVar16 + 1;
      iVar21 = iVar21 + 1;
    } while (iVar21 < 0x40);
  }
  FUN_80286114(iVar20);
  return;
}

