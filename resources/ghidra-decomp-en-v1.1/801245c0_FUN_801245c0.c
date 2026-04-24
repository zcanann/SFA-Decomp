// Function: FUN_801245c0
// Entry: 801245c0
// Size: 1208 bytes

void FUN_801245c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  short *psVar3;
  short *psVar4;
  short *extraout_r4;
  short *psVar5;
  short *psVar6;
  short *psVar7;
  short *psVar8;
  undefined1 *puVar9;
  uint in_r10;
  int iVar10;
  short *psVar11;
  short *psVar12;
  int *piVar13;
  int *piVar14;
  undefined1 *puVar15;
  short *psVar16;
  int iVar17;
  int iVar18;
  undefined8 extraout_f1;
  undefined8 uVar19;
  undefined8 uVar20;
  short local_a8 [84];
  
  uVar20 = FUN_8028682c();
  psVar3 = (short *)((ulonglong)uVar20 >> 0x20);
  psVar4 = (short *)uVar20;
  psVar16 = &DAT_803a9d98;
  psVar11 = local_a8;
  psVar12 = &DAT_803a9998;
  puVar15 = &DAT_803a9898;
  iVar18 = 8;
  psVar6 = psVar16;
  psVar7 = psVar11;
  psVar8 = psVar12;
  puVar9 = puVar15;
  do {
    *psVar7 = *psVar6;
    psVar5 = (short *)0xffffffff;
    *psVar6 = -1;
    iVar10 = 0;
    *psVar8 = 0;
    *puVar9 = 1;
    psVar7[1] = psVar6[1];
    psVar6[1] = -1;
    psVar8[1] = 0;
    puVar9[1] = 1;
    psVar7[2] = psVar6[2];
    psVar6[2] = -1;
    psVar8[2] = 0;
    puVar9[2] = 1;
    psVar7[3] = psVar6[3];
    psVar6[3] = -1;
    psVar8[3] = 0;
    puVar9[3] = 1;
    psVar7[4] = psVar6[4];
    psVar6[4] = -1;
    psVar8[4] = 0;
    puVar9[4] = 1;
    psVar7[5] = psVar6[5];
    psVar6[5] = -1;
    psVar8[5] = 0;
    puVar9[5] = 1;
    psVar7[6] = psVar6[6];
    psVar6[6] = -1;
    psVar8[6] = 0;
    puVar9[6] = 1;
    psVar7[7] = psVar6[7];
    psVar6[7] = -1;
    psVar8[7] = 0;
    puVar9[7] = 1;
    psVar6 = psVar6 + 8;
    psVar7 = psVar7 + 8;
    psVar8 = psVar8 + 8;
    puVar9 = puVar9 + 8;
    iVar18 = iVar18 + -1;
  } while (iVar18 != 0);
  iVar17 = 0;
  iVar18 = 0;
  piVar14 = &DAT_803a9c98;
  DAT_803a9c98 = 0xffffffff;
  uVar19 = extraout_f1;
  if ((char)uVar20 == '\0') {
    DAT_803de514 = 0xffff;
    while( true ) {
      psVar12 = (short *)((ulonglong)uVar20 >> 0x20);
      psVar4 = (short *)uVar20;
      if (*psVar12 < 0) break;
      uVar1 = FUN_80020078((int)*psVar12);
      if (uVar1 != 0) {
        if (psVar3 == &DAT_8031c130) {
          if ((psVar12[1] < 0) || (uVar2 = FUN_80020078((int)psVar12[1]), uVar2 == 0)) {
            psVar4 = (short *)(&DAT_803a9450 + iVar10);
            *(short *)((int)&DAT_803a9d98 + iVar10) = psVar12[3];
            *(int *)((int)&DAT_803a9c98 + iVar18) = (int)*psVar12;
            *(int *)((int)&DAT_803a9b98 + iVar18) = (int)psVar12[2];
            *(int *)((int)&DAT_803a9a98 + iVar18) = (int)psVar12[1];
            (&DAT_803a9898)[iVar17] = (char)uVar1;
            *(short *)((int)&DAT_803a9998 + iVar10) = psVar12[6];
            *(short *)((int)&DAT_803a9a18 + iVar10) = psVar12[5];
            (&DAT_803a9958)[iVar17] = *(undefined *)(psVar12 + 7);
            (&DAT_803a9918)[iVar17] = *(undefined *)((int)psVar12 + 0xf);
            if ((psVar12[2] < 0) || (uVar1 = FUN_80020078((int)psVar12[2]), uVar1 == 0)) {
              (&DAT_803a98d8)[iVar17] = 1;
            }
            else {
              (&DAT_803a98d8)[iVar17] = 0;
            }
            iVar17 = iVar17 + 1;
            iVar18 = iVar18 + 4;
            iVar10 = iVar10 + 2;
          }
        }
        else if ((psVar12[1] < 0) || (uVar2 = FUN_80020078((int)psVar12[1]), uVar2 == 0)) {
          if ((DAT_803de516 != 0) && ((int)DAT_803de516 == (int)*psVar12)) {
            DAT_803de514 = (undefined2)iVar17;
          }
          psVar4 = (short *)(&DAT_803a9450 + iVar10);
          *(short *)((int)&DAT_803a9d98 + iVar10) = psVar12[3];
          *(int *)((int)&DAT_803a9c98 + iVar18) = (int)*psVar12;
          *(int *)((int)&DAT_803a9b98 + iVar18) = (int)psVar12[2];
          *(int *)((int)&DAT_803a9a98 + iVar18) = (int)psVar12[1];
          (&DAT_803a9898)[iVar17] = (char)uVar1;
          *(short *)((int)&DAT_803a9998 + iVar10) = psVar12[6];
          *(short *)((int)&DAT_803a9a18 + iVar10) = psVar12[5];
          (&DAT_803a9958)[iVar17] = *(undefined *)(psVar12 + 7);
          (&DAT_803a9918)[iVar17] = *(undefined *)((int)psVar12 + 0xf);
          if ((psVar12[2] < 0) || (uVar1 = FUN_80020078((int)psVar12[2]), uVar1 == 0)) {
            (&DAT_803a98d8)[iVar17] = 1;
          }
          else {
            (&DAT_803a98d8)[iVar17] = 0;
          }
          iVar17 = iVar17 + 1;
          iVar18 = iVar18 + 4;
          iVar10 = iVar10 + 2;
        }
      }
      uVar20 = CONCAT44(psVar12 + 8,psVar4);
    }
  }
  else {
    FUN_8002ba84();
    uVar1 = DAT_803de3bc;
    in_r10 = DAT_803de3b8;
    if (DAT_803de3b8 == 0xffffffff) {
      if (DAT_803de504 == 2) {
        DAT_803de504 = 0;
        DAT_803de4f4 = 0xffff;
      }
    }
    else {
      psVar5 = &DAT_803a9a18;
      psVar6 = (short *)&DAT_803a9958;
      psVar7 = (short *)&DAT_803a9918;
      psVar8 = (short *)&DAT_803a98d8;
      puVar9 = (undefined1 *)(uint)DAT_803de50a;
      psVar4 = psVar16;
      for (; -1 < *psVar3; psVar3 = psVar3 + 8) {
        if ((uVar1 & (int)*psVar3) == 0) {
          if ((DAT_803de504 == 2) && (puVar9 == (undefined1 *)(int)psVar3[2])) {
            DAT_803de504 = 0;
            DAT_803de4f4 = 0xffff;
          }
        }
        else {
          *psVar4 = psVar3[3];
          *puVar15 = 1;
          *piVar14 = (int)psVar3[2];
          *psVar12 = psVar3[6];
          *psVar5 = psVar3[5];
          *(undefined *)psVar6 = *(undefined *)(psVar3 + 7);
          *(undefined *)psVar7 = *(undefined *)((int)psVar3 + 0xf);
          if ((in_r10 & (int)*psVar3) == 0) {
            *(undefined *)psVar8 = 0;
          }
          else {
            *(undefined *)psVar8 = 1;
          }
          psVar4 = psVar4 + 1;
          puVar15 = puVar15 + 1;
          piVar14 = piVar14 + 1;
          psVar12 = psVar12 + 1;
          psVar5 = psVar5 + 1;
          psVar6 = (short *)((int)psVar6 + 1);
          psVar7 = (short *)((int)psVar7 + 1);
          psVar8 = (short *)((int)psVar8 + 1);
        }
      }
    }
  }
  iVar18 = 0;
  piVar13 = &DAT_803a9e18;
  psVar3 = psVar16;
  piVar14 = piVar13;
  do {
    if (((-1 < *psVar11) && (*psVar11 != *psVar3)) && (*piVar14 != 0)) {
      uVar19 = FUN_80054484();
      *piVar14 = 0;
      psVar4 = extraout_r4;
    }
    psVar11 = psVar11 + 1;
    psVar3 = psVar3 + 1;
    piVar14 = piVar14 + 1;
    iVar18 = iVar18 + 1;
  } while (iVar18 < 0x40);
  iVar18 = FUN_800431a4();
  if (iVar18 == 0) {
    iVar18 = 0;
    do {
      if ((-1 < *psVar16) && (*piVar13 == 0)) {
        iVar10 = FUN_80054ed0(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)*psVar16,psVar4,psVar5,psVar6,psVar7,psVar8,puVar9,in_r10);
        *piVar13 = iVar10;
      }
      psVar16 = psVar16 + 1;
      piVar13 = piVar13 + 1;
      iVar18 = iVar18 + 1;
    } while (iVar18 < 0x40);
  }
  FUN_80286878();
  return;
}

