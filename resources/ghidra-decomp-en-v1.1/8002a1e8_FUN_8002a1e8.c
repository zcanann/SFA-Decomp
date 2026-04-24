// Function: FUN_8002a1e8
// Entry: 8002a1e8
// Size: 692 bytes

/* WARNING: Removing unreachable block (ram,0x8002a458) */
/* WARNING: Removing unreachable block (ram,0x8002a438) */
/* WARNING: Removing unreachable block (ram,0x8002a444) */
/* WARNING: Removing unreachable block (ram,0x8002a3e8) */
/* WARNING: Removing unreachable block (ram,0x8002a37c) */
/* WARNING: Removing unreachable block (ram,0x8002a40c) */
/* WARNING: Removing unreachable block (ram,0x8002a368) */
/* WARNING: Removing unreachable block (ram,0x8002a3bc) */
/* WARNING: Removing unreachable block (ram,0x8002a398) */
/* WARNING: Removing unreachable block (ram,0x8002a350) */
/* WARNING: Removing unreachable block (ram,0x8002a344) */
/* WARNING: Removing unreachable block (ram,0x8002a318) */
/* WARNING: Removing unreachable block (ram,0x8002a300) */
/* WARNING: Removing unreachable block (ram,0x8002a2f4) */
/* WARNING: Removing unreachable block (ram,0x8002a2c8) */
/* WARNING: Removing unreachable block (ram,0x8002a2b0) */
/* WARNING: Removing unreachable block (ram,0x8002a2a4) */
/* WARNING: Removing unreachable block (ram,0x8002a288) */
/* WARNING: Removing unreachable block (ram,0x8002a284) */
/* WARNING: Removing unreachable block (ram,0x8002a27c) */
/* WARNING: Removing unreachable block (ram,0x8002a274) */
/* WARNING: Removing unreachable block (ram,0x8002a270) */
/* WARNING: Removing unreachable block (ram,0x8002a26c) */
/* WARNING: Removing unreachable block (ram,0x8002a264) */
/* WARNING: Removing unreachable block (ram,0x8002a25c) */
/* WARNING: Removing unreachable block (ram,0x8002a258) */
/* WARNING: Removing unreachable block (ram,0x8002a250) */
/* WARNING: Removing unreachable block (ram,0x8002a248) */
/* WARNING: Removing unreachable block (ram,0x8002a244) */
/* WARNING: Removing unreachable block (ram,0x8002a240) */
/* WARNING: Removing unreachable block (ram,0x8002a234) */
/* WARNING: Removing unreachable block (ram,0x8002a22c) */
/* WARNING: Removing unreachable block (ram,0x8002a3a4) */
/* WARNING: Removing unreachable block (ram,0x8002a3f4) */

void FUN_8002a1e8(float *param_1,float *param_2,float *param_3,float *param_4,float *param_5,
                 int param_6)

{
  float *pfVar1;
  float *pfVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  longlong lVar6;
  byte bVar7;
  byte bVar8;
  float *pfVar9;
  float *pfVar10;
  int iVar11;
  uint unaff_GQR7;
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
  double dVar28;
  double dVar29;
  double dVar30;
  double dVar31;
  double dVar32;
  double dVar33;
  double dVar34;
  double dVar35;
  double dVar36;
  double dVar37;
  double dVar38;
  double dVar39;
  double dVar40;
  double dVar41;
  double dVar42;
  
  iVar11 = param_6 + -1;
  dVar12 = (double)*param_1;
  dVar32 = (double)param_1[1];
  dVar13 = (double)param_1[2];
  bVar3 = (byte)(unaff_GQR7 >> 0x10);
  bVar4 = bVar3 & 7;
  bVar5 = (byte)(unaff_GQR7 >> 0x18);
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar18 = (double)(lVar6 * (longlong)(double)*(char *)param_4);
    dVar35 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_4 + 1));
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar18 = (double)(lVar6 * (longlong)(double)*(short *)param_4);
    dVar35 = (double)(lVar6 * (longlong)(double)*(short *)((int)param_4 + 2));
  }
  else {
    dVar18 = (double)*param_4;
    dVar35 = (double)param_4[1];
  }
  pfVar1 = (float *)((int)param_4 + 2);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar21 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar21 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
  }
  else {
    dVar21 = (double)*pfVar1;
  }
  lVar6 = ldexpf(0xc3);
  dVar31 = (double)(lVar6 * (longlong)(double)*(char *)param_3);
  dVar42 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 1));
  dVar14 = (double)param_1[3];
  dVar33 = (double)param_1[4];
  dVar15 = (double)param_1[5];
  dVar17 = (double)param_1[8];
  dVar25 = (double)*param_2;
  dVar39 = (double)param_2[1];
  dVar16 = (double)param_1[6];
  dVar34 = (double)param_1[7];
  dVar26 = (double)param_2[2];
  dVar27 = (double)param_2[3];
  dVar40 = (double)param_2[4];
  dVar28 = (double)param_2[5];
  dVar29 = (double)param_2[6];
  dVar41 = (double)param_2[7];
  dVar30 = (double)param_2[8];
  pfVar1 = (float *)((int)param_4 + 3);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar19 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
    dVar36 = (double)(lVar6 * (longlong)(double)*(char *)(param_4 + 1));
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar19 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
    dVar36 = (double)(lVar6 * (longlong)(double)*(short *)((int)param_4 + 5));
  }
  else {
    dVar19 = (double)*pfVar1;
    dVar36 = (double)*(float *)((int)param_4 + 7);
  }
  pfVar1 = (float *)((int)param_4 + 5);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar22 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar22 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
  }
  else {
    dVar22 = (double)*pfVar1;
  }
  dVar24 = (dVar29 * dVar21 + dVar27 * dVar35 + dVar25 * dVar18) * dVar42 +
           (dVar16 * dVar21 + dVar14 * dVar35 + dVar12 * dVar18) * dVar31;
  dVar38 = (dVar41 * dVar21 + dVar40 * dVar35 + dVar39 * dVar18) * dVar42 +
           (dVar34 * dVar21 + dVar33 * dVar35 + dVar32 * dVar18) * dVar31;
  dVar18 = (dVar30 * dVar21 + dVar28 * dVar35 + dVar26 * dVar18) * dVar42 +
           (dVar17 * dVar21 + dVar15 * dVar35 + dVar13 * dVar18) * dVar31;
  bVar4 = (byte)unaff_GQR7;
  bVar7 = bVar4 & 7;
  bVar8 = (byte)(unaff_GQR7 >> 8);
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar35 = 1.0;
  }
  else {
    dVar35 = (double)ldexpf(bVar8 & 0x3f);
  }
  if (bVar7 == 4 || bVar7 == 6) {
    *(char *)param_5 = (char)(dVar35 * dVar24);
    *(char *)((int)param_5 + 1) = (char)(dVar35 * dVar38);
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    *(short *)param_5 = (short)(dVar35 * dVar24);
    *(short *)((int)param_5 + 2) = (short)(dVar35 * dVar38);
  }
  else {
    *param_5 = (float)dVar24;
    param_5[1] = (float)dVar38;
  }
  pfVar1 = (float *)((int)param_5 + 2);
  bVar7 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar35 = 1.0;
  }
  else {
    dVar35 = (double)ldexpf(bVar8 & 0x3f);
  }
  if (bVar7 == 4 || bVar7 == 6) {
    *(char *)pfVar1 = (char)(dVar35 * dVar18);
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    *(short *)pfVar1 = (short)(dVar35 * dVar18);
  }
  else {
    *pfVar1 = (float)dVar18;
  }
  pfVar1 = (float *)((int)param_4 + 6);
  bVar7 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar7 == 4 || bVar7 == 6) {
    dVar18 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
    dVar35 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_4 + 7));
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    dVar18 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
    dVar35 = (double)(lVar6 * (longlong)(double)*(short *)(param_4 + 2));
  }
  else {
    dVar18 = (double)*pfVar1;
    dVar35 = (double)*(float *)((int)param_4 + 10);
  }
  pfVar1 = param_4 + 2;
  bVar7 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar7 == 4 || bVar7 == 6) {
    dVar21 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    dVar21 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
  }
  else {
    dVar21 = (double)*pfVar1;
  }
  dVar24 = (dVar29 * dVar22 + dVar27 * dVar36 + dVar25 * dVar19) * dVar42 +
           (dVar16 * dVar22 + dVar14 * dVar36 + dVar12 * dVar19) * dVar31;
  dVar38 = (dVar41 * dVar22 + dVar40 * dVar36 + dVar39 * dVar19) * dVar42 +
           (dVar34 * dVar22 + dVar33 * dVar36 + dVar32 * dVar19) * dVar31;
  dVar19 = (dVar30 * dVar22 + dVar28 * dVar36 + dVar26 * dVar19) * dVar42 +
           (dVar17 * dVar22 + dVar15 * dVar36 + dVar13 * dVar19) * dVar31;
  pfVar1 = (float *)((int)param_5 + 3);
  bVar7 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar36 = 1.0;
  }
  else {
    dVar36 = (double)ldexpf(bVar8 & 0x3f);
  }
  if (bVar7 == 4 || bVar7 == 6) {
    *(char *)pfVar1 = (char)(dVar36 * dVar24);
    *(char *)(param_5 + 1) = (char)(dVar36 * dVar38);
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    *(short *)pfVar1 = (short)(dVar36 * dVar24);
    *(short *)((int)param_5 + 5) = (short)(dVar36 * dVar38);
  }
  else {
    *pfVar1 = (float)dVar24;
    *(float *)((int)param_5 + 7) = (float)dVar38;
  }
  pfVar1 = (float *)((int)param_5 + 5);
  bVar7 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar36 = 1.0;
  }
  else {
    dVar36 = (double)ldexpf(bVar8 & 0x3f);
  }
  if (bVar7 == 4 || bVar7 == 6) {
    *(char *)pfVar1 = (char)(dVar36 * dVar19);
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    *(short *)pfVar1 = (short)(dVar36 * dVar19);
  }
  else {
    *pfVar1 = (float)dVar19;
  }
  pfVar9 = (float *)((int)param_4 + 9);
  bVar7 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar7 == 4 || bVar7 == 6) {
    dVar19 = (double)(lVar6 * (longlong)(double)*(char *)pfVar9);
    dVar36 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_4 + 10));
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    dVar19 = (double)(lVar6 * (longlong)(double)*(short *)pfVar9);
    dVar36 = (double)(lVar6 * (longlong)(double)*(short *)((int)param_4 + 0xb));
  }
  else {
    dVar19 = (double)*pfVar9;
    dVar36 = (double)*(float *)((int)param_4 + 0xd);
  }
  pfVar9 = (float *)((int)param_4 + 0xb);
  bVar7 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar7 == 4 || bVar7 == 6) {
    dVar22 = (double)(lVar6 * (longlong)(double)*(char *)pfVar9);
  }
  else if (bVar7 == 5 || bVar7 == 7) {
    dVar22 = (double)(lVar6 * (longlong)(double)*(short *)pfVar9);
  }
  else {
    dVar22 = (double)*pfVar9;
  }
  dVar24 = (dVar29 * dVar21 + dVar27 * dVar35 + dVar25 * dVar18) * dVar42 +
           (dVar16 * dVar21 + dVar14 * dVar35 + dVar12 * dVar18) * dVar31;
  dVar38 = (dVar41 * dVar21 + dVar40 * dVar35 + dVar39 * dVar18) * dVar42 +
           (dVar34 * dVar21 + dVar33 * dVar35 + dVar32 * dVar18) * dVar31;
  dVar18 = (dVar30 * dVar21 + dVar28 * dVar35 + dVar26 * dVar18) * dVar42 +
           (dVar17 * dVar21 + dVar15 * dVar35 + dVar13 * dVar18) * dVar31;
  do {
    pfVar10 = pfVar1;
    pfVar1 = (float *)((int)pfVar10 + 1);
    bVar7 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar35 = 1.0;
    }
    else {
      dVar35 = (double)ldexpf(bVar8 & 0x3f);
    }
    if (bVar7 == 4 || bVar7 == 6) {
      *(char *)pfVar1 = (char)(dVar35 * dVar24);
      *(char *)((int)pfVar10 + 2) = (char)(dVar35 * dVar38);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      *(short *)pfVar1 = (short)(dVar35 * dVar24);
      *(short *)((int)pfVar10 + 3) = (short)(dVar35 * dVar38);
    }
    else {
      *pfVar1 = (float)dVar24;
      *(float *)((int)pfVar10 + 5) = (float)dVar38;
    }
    pfVar1 = (float *)((int)pfVar10 + 3);
    bVar7 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar35 = 1.0;
    }
    else {
      dVar35 = (double)ldexpf(bVar8 & 0x3f);
    }
    if (bVar7 == 4 || bVar7 == 6) {
      *(char *)pfVar1 = (char)(dVar35 * dVar18);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      *(short *)pfVar1 = (short)(dVar35 * dVar18);
    }
    else {
      *pfVar1 = (float)dVar18;
    }
    lVar6 = ldexpf(0xc3);
    dVar18 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 2));
    dVar35 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 3));
    pfVar1 = (float *)((int)pfVar9 + 1);
    bVar7 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar7 == 4 || bVar7 == 6) {
      dVar21 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
      dVar31 = (double)(lVar6 * (longlong)(double)*(char *)((int)pfVar9 + 2));
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      dVar21 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
      dVar31 = (double)(lVar6 * (longlong)(double)*(short *)((int)pfVar9 + 3));
    }
    else {
      dVar21 = (double)*pfVar1;
      dVar31 = (double)*(float *)((int)pfVar9 + 5);
    }
    pfVar1 = (float *)((int)pfVar9 + 3);
    bVar7 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar7 == 4 || bVar7 == 6) {
      dVar42 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      dVar42 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
    }
    else {
      dVar42 = (double)*pfVar1;
    }
    dVar24 = (dVar29 * dVar22 + dVar27 * dVar36 + dVar25 * dVar19) * dVar35 +
             (dVar16 * dVar22 + dVar14 * dVar36 + dVar12 * dVar19) * dVar18;
    dVar38 = (dVar41 * dVar22 + dVar40 * dVar36 + dVar39 * dVar19) * dVar35 +
             (dVar34 * dVar22 + dVar33 * dVar36 + dVar32 * dVar19) * dVar18;
    dVar19 = (dVar30 * dVar22 + dVar28 * dVar36 + dVar26 * dVar19) * dVar35 +
             (dVar17 * dVar22 + dVar15 * dVar36 + dVar13 * dVar19) * dVar18;
    pfVar1 = pfVar10 + 1;
    bVar7 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar36 = 1.0;
    }
    else {
      dVar36 = (double)ldexpf(bVar8 & 0x3f);
    }
    if (bVar7 == 4 || bVar7 == 6) {
      *(char *)pfVar1 = (char)(dVar36 * dVar24);
      *(char *)((int)pfVar10 + 5) = (char)(dVar36 * dVar38);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      *(short *)pfVar1 = (short)(dVar36 * dVar24);
      *(short *)((int)pfVar10 + 6) = (short)(dVar36 * dVar38);
    }
    else {
      *pfVar1 = (float)dVar24;
      pfVar10[2] = (float)dVar38;
    }
    pfVar1 = (float *)((int)pfVar10 + 6);
    bVar7 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar36 = 1.0;
    }
    else {
      dVar36 = (double)ldexpf(bVar8 & 0x3f);
    }
    if (bVar7 == 4 || bVar7 == 6) {
      *(char *)pfVar1 = (char)(dVar36 * dVar19);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      *(short *)pfVar1 = (short)(dVar36 * dVar19);
    }
    else {
      *pfVar1 = (float)dVar19;
    }
    pfVar1 = pfVar9 + 1;
    bVar7 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar7 == 4 || bVar7 == 6) {
      dVar20 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
      dVar37 = (double)(lVar6 * (longlong)(double)*(char *)((int)pfVar9 + 5));
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      dVar20 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
      dVar37 = (double)(lVar6 * (longlong)(double)*(short *)((int)pfVar9 + 6));
    }
    else {
      dVar20 = (double)*pfVar1;
      dVar37 = (double)pfVar9[2];
    }
    pfVar1 = (float *)((int)pfVar9 + 6);
    bVar7 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar7 == 4 || bVar7 == 6) {
      dVar23 = (double)(lVar6 * (longlong)(double)*(char *)pfVar1);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      dVar23 = (double)(lVar6 * (longlong)(double)*(short *)pfVar1);
    }
    else {
      dVar23 = (double)*pfVar1;
    }
    dVar19 = (dVar29 * dVar42 + dVar27 * dVar31 + dVar25 * dVar21) * dVar35 +
             (dVar16 * dVar42 + dVar14 * dVar31 + dVar12 * dVar21) * dVar18;
    dVar36 = (dVar41 * dVar42 + dVar40 * dVar31 + dVar39 * dVar21) * dVar35 +
             (dVar34 * dVar42 + dVar33 * dVar31 + dVar32 * dVar21) * dVar18;
    dVar21 = (dVar30 * dVar42 + dVar28 * dVar31 + dVar26 * dVar21) * dVar35 +
             (dVar17 * dVar42 + dVar15 * dVar31 + dVar13 * dVar21) * dVar18;
    pfVar1 = (float *)((int)pfVar10 + 7);
    bVar7 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar31 = 1.0;
    }
    else {
      dVar31 = (double)ldexpf(bVar8 & 0x3f);
    }
    if (bVar7 == 4 || bVar7 == 6) {
      *(char *)pfVar1 = (char)(dVar31 * dVar19);
      *(char *)(pfVar10 + 2) = (char)(dVar31 * dVar36);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      *(short *)pfVar1 = (short)(dVar31 * dVar19);
      *(short *)((int)pfVar10 + 9) = (short)(dVar31 * dVar36);
    }
    else {
      *pfVar1 = (float)dVar19;
      *(float *)((int)pfVar10 + 0xb) = (float)dVar36;
    }
    pfVar1 = (float *)((int)pfVar10 + 9);
    bVar7 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar31 = 1.0;
    }
    else {
      dVar31 = (double)ldexpf(bVar8 & 0x3f);
    }
    if (bVar7 == 4 || bVar7 == 6) {
      *(char *)pfVar1 = (char)(dVar31 * dVar21);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      *(short *)pfVar1 = (short)(dVar31 * dVar21);
    }
    else {
      *pfVar1 = (float)dVar21;
    }
    pfVar2 = (float *)((int)pfVar9 + 7);
    bVar7 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar7 == 4 || bVar7 == 6) {
      dVar19 = (double)(lVar6 * (longlong)(double)*(char *)pfVar2);
      dVar36 = (double)(lVar6 * (longlong)(double)*(char *)(pfVar9 + 2));
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      dVar19 = (double)(lVar6 * (longlong)(double)*(short *)pfVar2);
      dVar36 = (double)(lVar6 * (longlong)(double)*(short *)((int)pfVar9 + 9));
    }
    else {
      dVar19 = (double)*pfVar2;
      dVar36 = (double)*(float *)((int)pfVar9 + 0xb);
    }
    pfVar9 = (float *)((int)pfVar9 + 9);
    bVar7 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar7 == 4 || bVar7 == 6) {
      dVar22 = (double)(lVar6 * (longlong)(double)*(char *)pfVar9);
    }
    else if (bVar7 == 5 || bVar7 == 7) {
      dVar22 = (double)(lVar6 * (longlong)(double)*(short *)pfVar9);
    }
    else {
      dVar22 = (double)*pfVar9;
    }
    dVar24 = (dVar29 * dVar23 + dVar27 * dVar37 + dVar25 * dVar20) * dVar35 +
             (dVar16 * dVar23 + dVar14 * dVar37 + dVar12 * dVar20) * dVar18;
    dVar38 = (dVar41 * dVar23 + dVar40 * dVar37 + dVar39 * dVar20) * dVar35 +
             (dVar34 * dVar23 + dVar33 * dVar37 + dVar32 * dVar20) * dVar18;
    dVar18 = (dVar30 * dVar23 + dVar28 * dVar37 + dVar26 * dVar20) * dVar35 +
             (dVar17 * dVar23 + dVar15 * dVar37 + dVar13 * dVar20) * dVar18;
    iVar11 = iVar11 + -1;
    param_3 = (float *)((int)param_3 + 2);
  } while (iVar11 != 0);
  pfVar1 = (float *)((int)pfVar10 + 10);
  bVar3 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar12 = 1.0;
  }
  else {
    dVar12 = (double)ldexpf(bVar8 & 0x3f);
  }
  if (bVar3 == 4 || bVar3 == 6) {
    *(char *)pfVar1 = (char)(dVar12 * dVar24);
    *(char *)((int)pfVar10 + 0xb) = (char)(dVar12 * dVar38);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    *(short *)pfVar1 = (short)(dVar12 * dVar24);
    *(short *)(pfVar10 + 3) = (short)(dVar12 * dVar38);
  }
  else {
    *pfVar1 = (float)dVar24;
    *(float *)((int)pfVar10 + 0xe) = (float)dVar38;
  }
  pfVar10 = pfVar10 + 3;
  bVar4 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar12 = 1.0;
  }
  else {
    dVar12 = (double)ldexpf(bVar8 & 0x3f);
  }
  if (bVar4 == 4 || bVar4 == 6) {
    *(char *)pfVar10 = (char)(dVar12 * dVar18);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    *(short *)pfVar10 = (short)(dVar12 * dVar18);
  }
  else {
    *pfVar10 = (float)dVar18;
  }
  return;
}

