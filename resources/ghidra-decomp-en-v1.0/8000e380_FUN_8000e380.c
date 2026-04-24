// Function: FUN_8000e380
// Entry: 8000e380
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x8000e604) */

void FUN_8000e380(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  double dVar25;
  double dVar26;
  undefined8 in_f31;
  double dVar27;
  double dVar28;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  DAT_803dc884 = DAT_803dc886;
  if (DAT_803dc880 != 0) {
    DAT_803dc880 = DAT_803dc880 - (ushort)DAT_803db410;
    if (DAT_803dc880 < 0) {
      DAT_803dc880 = 0;
    }
    FLOAT_803db264 =
         ((float)((double)CONCAT44(0x43300000,(int)DAT_803dc880 ^ 0x80000000) - DOUBLE_803de618) /
         (float)((double)CONCAT44(0x43300000,(int)DAT_803dc882 ^ 0x80000000) - DOUBLE_803de618)) *
         (FLOAT_803dc8ac - FLOAT_803dc8a8) + FLOAT_803dc8a8;
  }
  DAT_803dc888 = 0;
  uVar2 = (uint)DAT_803dc88d;
  iVar3 = uVar2 * 0x60;
  if ((&DAT_8033822d)[iVar3] == '\0') {
    (&DAT_8033822c)[iVar3] = (&DAT_8033822c)[iVar3] + -1;
    fVar1 = FLOAT_803de5f4;
    while ((char)(&DAT_8033822c)[iVar3] < '\0') {
      (&DAT_8033822c)[iVar3] = (&DAT_8033822c)[iVar3] + '\x01';
      (&DAT_803381fc)[uVar2 * 0x18] = fVar1 * -(float)(&DAT_803381fc)[uVar2 * 0x18];
    }
  }
  else if ((&DAT_8033822d)[iVar3] == '\x01') {
    dVar26 = (double)(-(float)(&DAT_8033820c)[uVar2 * 0x18] * (float)(&DAT_80338208)[uVar2 * 0x18]);
    dVar27 = (double)FLOAT_803de5f0;
    iVar4 = 2;
    dVar8 = dVar27;
    dVar7 = dVar27;
    dVar25 = dVar26;
    dVar28 = dVar27;
    do {
      dVar6 = (double)(float)(dVar8 * (double)(float)(dVar7 + dVar27));
      dVar9 = (double)(float)((double)(float)(dVar7 + dVar27) + dVar27);
      dVar17 = (double)(float)((double)(float)(dVar25 * dVar26) * dVar26);
      dVar7 = (double)(float)(dVar6 * dVar9);
      dVar10 = (double)(float)(dVar9 + dVar27);
      dVar18 = (double)(float)(dVar17 * dVar26);
      dVar9 = (double)(float)(dVar7 * dVar10);
      dVar11 = (double)(float)(dVar10 + dVar27);
      dVar19 = (double)(float)(dVar18 * dVar26);
      dVar10 = (double)(float)(dVar9 * dVar11);
      dVar12 = (double)(float)(dVar11 + dVar27);
      dVar20 = (double)(float)(dVar19 * dVar26);
      dVar11 = (double)(float)(dVar10 * dVar12);
      dVar13 = (double)(float)(dVar12 + dVar27);
      dVar21 = (double)(float)(dVar20 * dVar26);
      dVar12 = (double)(float)(dVar11 * dVar13);
      dVar14 = (double)(float)(dVar13 + dVar27);
      dVar22 = (double)(float)(dVar21 * dVar26);
      dVar13 = (double)(float)(dVar12 * dVar14);
      dVar15 = (double)(float)(dVar14 + dVar27);
      dVar23 = (double)(float)(dVar22 * dVar26);
      dVar14 = (double)(float)(dVar13 * dVar15);
      dVar16 = (double)(float)(dVar15 + dVar27);
      dVar24 = (double)(float)(dVar23 * dVar26);
      dVar15 = (double)(float)(dVar14 * dVar16);
      dVar28 = (double)((float)(dVar28 + (double)(float)(dVar25 / dVar8)) +
                        (float)((double)(float)(dVar25 * dVar26) / dVar6) + (float)(dVar17 / dVar7)
                        + (float)(dVar18 / dVar9) + (float)(dVar19 / dVar10) +
                        (float)(dVar20 / dVar11) + (float)(dVar21 / dVar12) +
                        (float)(dVar22 / dVar13) + (float)(dVar23 / dVar14) +
                       (float)(dVar24 / dVar15));
      dVar7 = (double)(float)(dVar16 + dVar27);
      dVar25 = (double)(float)(dVar24 * dVar26);
      dVar8 = (double)(float)(dVar15 * dVar7);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    dVar8 = (double)FUN_80294204((double)((FLOAT_803de5f8 *
                                          FLOAT_803de5fc * (float)(&DAT_80338204)[uVar2 * 0x18] *
                                          (float)(&DAT_80338208)[uVar2 * 0x18]) / FLOAT_803de600));
    (&DAT_803381fc)[uVar2 * 0x18] =
         (float)((double)(float)((double)(float)(&DAT_80338200)[uVar2 * 0x18] * dVar28) * dVar8);
    if (((float)(&DAT_803381fc)[uVar2 * 0x18] < FLOAT_803de604) &&
       (FLOAT_803de608 < (float)(&DAT_803381fc)[uVar2 * 0x18])) {
      (&DAT_803381fc)[uVar2 * 0x18] = FLOAT_803de60c;
      (&DAT_8033822d)[iVar3] = 0xff;
    }
    (&DAT_80338208)[uVar2 * 0x18] =
         (float)(&DAT_80338208)[uVar2 * 0x18] + FLOAT_803db414 / FLOAT_803de610;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

