// Function: FUN_8000e3a0
// Entry: 8000e3a0
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x8000e624) */

void FUN_8000e3a0(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint unaff_GQR0;
  double dVar5;
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
  double dVar27;
  
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  DAT_803dd504 = DAT_803dd506;
  if (DAT_803dd500 != 0) {
    DAT_803dd500 = DAT_803dd500 - (ushort)DAT_803dc070;
    if (DAT_803dd500 < 0) {
      DAT_803dd500 = 0;
    }
    FLOAT_803dbec4 =
         ((float)((double)CONCAT44(0x43300000,(int)DAT_803dd500 ^ 0x80000000) - DOUBLE_803df298) /
         (float)((double)CONCAT44(0x43300000,(int)DAT_803dd502 ^ 0x80000000) - DOUBLE_803df298)) *
         (FLOAT_803dd52c - FLOAT_803dd528) + FLOAT_803dd528;
  }
  DAT_803dd508 = 0;
  uVar2 = (uint)DAT_803dd50d;
  iVar3 = uVar2 * 0x60;
  if ((&DAT_80338e8d)[iVar3] == '\0') {
    (&DAT_80338e8c)[iVar3] = (&DAT_80338e8c)[iVar3] + -1;
    fVar1 = FLOAT_803df274;
    while ((char)(&DAT_80338e8c)[iVar3] < '\0') {
      (&DAT_80338e8c)[iVar3] = (&DAT_80338e8c)[iVar3] + '\x01';
      (&DAT_80338e5c)[uVar2 * 0x18] = fVar1 * -(float)(&DAT_80338e5c)[uVar2 * 0x18];
    }
  }
  else if ((&DAT_80338e8d)[iVar3] == '\x01') {
    dVar25 = (double)(-(float)(&DAT_80338e6c)[uVar2 * 0x18] * (float)(&DAT_80338e68)[uVar2 * 0x18]);
    dVar26 = (double)FLOAT_803df270;
    iVar4 = 2;
    dVar7 = dVar26;
    dVar6 = dVar26;
    dVar24 = dVar25;
    dVar27 = dVar26;
    do {
      dVar5 = (double)(float)(dVar7 * (double)(float)(dVar6 + dVar26));
      dVar8 = (double)(float)((double)(float)(dVar6 + dVar26) + dVar26);
      dVar16 = (double)(float)((double)(float)(dVar24 * dVar25) * dVar25);
      dVar6 = (double)(float)(dVar5 * dVar8);
      dVar9 = (double)(float)(dVar8 + dVar26);
      dVar17 = (double)(float)(dVar16 * dVar25);
      dVar8 = (double)(float)(dVar6 * dVar9);
      dVar10 = (double)(float)(dVar9 + dVar26);
      dVar18 = (double)(float)(dVar17 * dVar25);
      dVar9 = (double)(float)(dVar8 * dVar10);
      dVar11 = (double)(float)(dVar10 + dVar26);
      dVar19 = (double)(float)(dVar18 * dVar25);
      dVar10 = (double)(float)(dVar9 * dVar11);
      dVar12 = (double)(float)(dVar11 + dVar26);
      dVar20 = (double)(float)(dVar19 * dVar25);
      dVar11 = (double)(float)(dVar10 * dVar12);
      dVar13 = (double)(float)(dVar12 + dVar26);
      dVar21 = (double)(float)(dVar20 * dVar25);
      dVar12 = (double)(float)(dVar11 * dVar13);
      dVar14 = (double)(float)(dVar13 + dVar26);
      dVar22 = (double)(float)(dVar21 * dVar25);
      dVar13 = (double)(float)(dVar12 * dVar14);
      dVar15 = (double)(float)(dVar14 + dVar26);
      dVar23 = (double)(float)(dVar22 * dVar25);
      dVar14 = (double)(float)(dVar13 * dVar15);
      dVar27 = (double)((float)(dVar27 + (double)(float)(dVar24 / dVar7)) +
                        (float)((double)(float)(dVar24 * dVar25) / dVar5) + (float)(dVar16 / dVar6)
                        + (float)(dVar17 / dVar8) + (float)(dVar18 / dVar9) +
                        (float)(dVar19 / dVar10) + (float)(dVar20 / dVar11) +
                        (float)(dVar21 / dVar12) + (float)(dVar22 / dVar13) +
                       (float)(dVar23 / dVar14));
      dVar6 = (double)(float)(dVar15 + dVar26);
      dVar24 = (double)(float)(dVar23 * dVar25);
      dVar7 = (double)(float)(dVar14 * dVar6);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    dVar7 = (double)FUN_80294964();
    (&DAT_80338e5c)[uVar2 * 0x18] =
         (float)((double)(float)((double)(float)(&DAT_80338e60)[uVar2 * 0x18] * dVar27) * dVar7);
    if (((float)(&DAT_80338e5c)[uVar2 * 0x18] < FLOAT_803df284) &&
       (FLOAT_803df288 < (float)(&DAT_80338e5c)[uVar2 * 0x18])) {
      (&DAT_80338e5c)[uVar2 * 0x18] = FLOAT_803df28c;
      (&DAT_80338e8d)[iVar3] = 0xff;
    }
    (&DAT_80338e68)[uVar2 * 0x18] =
         (float)(&DAT_80338e68)[uVar2 * 0x18] + FLOAT_803dc074 / FLOAT_803df290;
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
  }
  return;
}

