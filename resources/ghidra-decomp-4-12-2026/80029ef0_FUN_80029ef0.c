// Function: FUN_80029ef0
// Entry: 80029ef0
// Size: 388 bytes

/* WARNING: Removing unreachable block (ram,0x8002a030) */
/* WARNING: Removing unreachable block (ram,0x80029fe0) */
/* WARNING: Removing unreachable block (ram,0x80029ff4) */
/* WARNING: Removing unreachable block (ram,0x8002a01c) */
/* WARNING: Removing unreachable block (ram,0x8002a010) */
/* WARNING: Removing unreachable block (ram,0x80029fc8) */
/* WARNING: Removing unreachable block (ram,0x80029fbc) */
/* WARNING: Removing unreachable block (ram,0x80029fa4) */
/* WARNING: Removing unreachable block (ram,0x80029f9c) */
/* WARNING: Removing unreachable block (ram,0x80029f98) */
/* WARNING: Removing unreachable block (ram,0x80029f94) */
/* WARNING: Removing unreachable block (ram,0x80029f8c) */
/* WARNING: Removing unreachable block (ram,0x80029f84) */
/* WARNING: Removing unreachable block (ram,0x80029f80) */
/* WARNING: Removing unreachable block (ram,0x80029f7c) */
/* WARNING: Removing unreachable block (ram,0x80029f74) */
/* WARNING: Removing unreachable block (ram,0x80029f6c) */
/* WARNING: Removing unreachable block (ram,0x80029f68) */
/* WARNING: Removing unreachable block (ram,0x80029f60) */
/* WARNING: Removing unreachable block (ram,0x80029f58) */
/* WARNING: Removing unreachable block (ram,0x80029f54) */
/* WARNING: Removing unreachable block (ram,0x80029f50) */
/* WARNING: Removing unreachable block (ram,0x80029f4c) */
/* WARNING: Removing unreachable block (ram,0x80029f44) */
/* WARNING: Removing unreachable block (ram,0x80029f3c) */
/* WARNING: Removing unreachable block (ram,0x80029f34) */

void FUN_80029ef0(float *param_1,float *param_2,float *param_3,float *param_4,int param_5,
                 int param_6)

{
  float *pfVar1;
  float *pfVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  longlong lVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float fVar22;
  float fVar23;
  float fVar24;
  float fVar25;
  float fVar26;
  float fVar27;
  float fVar28;
  float fVar29;
  float fVar30;
  byte bVar31;
  byte bVar32;
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
  double dVar43;
  float *pfVar44;
  float *pfVar45;
  int iVar46;
  uint unaff_GQR7;
  double dVar47;
  double dVar48;
  double dVar49;
  double dVar50;
  double dVar51;
  double dVar52;
  double dVar53;
  double dVar54;
  double dVar55;
  double dVar56;
  double dVar57;
  double dVar58;
  
  iVar46 = param_6 + -1;
  fVar7 = *param_1;
  fVar23 = param_1[1];
  fVar8 = param_1[2];
  fVar9 = param_1[9];
  fVar24 = param_1[10];
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
    dVar47 = (double)(lVar6 * (longlong)(double)*(char *)param_4);
    dVar54 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_4 + 1));
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar47 = (double)(lVar6 * (longlong)(double)*(short *)param_4);
    dVar54 = (double)(lVar6 * (longlong)(double)*(short *)((int)param_4 + 2));
  }
  else {
    dVar47 = (double)*param_4;
    dVar54 = (double)param_4[1];
  }
  fVar10 = param_1[0xb];
  pfVar44 = param_4 + 1;
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar49 = (double)(lVar6 * (longlong)(double)*(char *)pfVar44);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar49 = (double)(lVar6 * (longlong)(double)*(short *)pfVar44);
  }
  else {
    dVar49 = (double)*pfVar44;
  }
  lVar6 = ldexpf(0xc3);
  dVar52 = (double)(lVar6 * (longlong)(double)*(char *)param_3);
  dVar57 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 1));
  fVar11 = param_1[3];
  fVar25 = param_1[4];
  fVar12 = param_1[5];
  fVar13 = param_1[8];
  fVar14 = *param_2;
  fVar26 = param_2[1];
  fVar15 = param_1[6];
  fVar27 = param_1[7];
  fVar16 = param_2[2];
  fVar17 = param_2[3];
  fVar28 = param_2[4];
  fVar18 = param_2[5];
  fVar19 = param_2[6];
  fVar29 = param_2[7];
  fVar20 = param_2[8];
  fVar21 = param_2[9];
  fVar30 = param_2[10];
  fVar22 = param_2[0xb];
  pfVar44 = (float *)((int)param_4 + 6);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar48 = (double)(lVar6 * (longlong)(double)*(char *)pfVar44);
    dVar55 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_4 + 7));
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar48 = (double)(lVar6 * (longlong)(double)*(short *)pfVar44);
    dVar55 = (double)(lVar6 * (longlong)(double)*(short *)(param_4 + 2));
  }
  else {
    dVar48 = (double)*pfVar44;
    dVar55 = (double)*(float *)((int)param_4 + 10);
  }
  pfVar44 = (float *)((int)param_4 + 10);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar50 = (double)(lVar6 * (longlong)(double)*(char *)pfVar44);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar50 = (double)(lVar6 * (longlong)(double)*(short *)pfVar44);
  }
  else {
    dVar50 = (double)*pfVar44;
  }
  dVar51 = ((double)fVar19 * dVar49 +
           (double)fVar17 * dVar54 + (double)fVar14 * dVar47 + (double)fVar21) * dVar57 +
           ((double)fVar15 * dVar49 +
           (double)fVar11 * dVar54 + (double)fVar7 * dVar47 + (double)fVar9) * dVar52;
  dVar56 = ((double)fVar29 * dVar49 +
           (double)fVar28 * dVar54 + (double)fVar26 * dVar47 + (double)fVar30) * dVar57 +
           ((double)fVar27 * dVar49 +
           (double)fVar25 * dVar54 + (double)fVar23 * dVar47 + (double)fVar24) * dVar52;
  dVar47 = ((double)fVar20 * dVar49 +
           (double)fVar18 * dVar54 + (double)fVar16 * dVar47 + (double)fVar22) * dVar57 +
           ((double)fVar13 * dVar49 +
           (double)fVar12 * dVar54 + (double)fVar8 * dVar47 + (double)fVar10) * dVar52;
  pfVar1 = (float *)(param_5 + -2);
  do {
    pfVar45 = pfVar1;
    dVar54 = (double)fVar7 * dVar48;
    dVar49 = (double)fVar23 * dVar48;
    pfVar1 = (float *)((int)pfVar45 + 2);
    bVar4 = (byte)unaff_GQR7;
    bVar31 = bVar4 & 7;
    bVar32 = (byte)(unaff_GQR7 >> 8);
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar52 = 1.0;
    }
    else {
      dVar52 = (double)ldexpf(bVar32 & 0x3f);
    }
    if (bVar31 == 4 || bVar31 == 6) {
      *(char *)pfVar1 = (char)(dVar52 * dVar51);
      *(char *)((int)pfVar45 + 3) = (char)(dVar52 * dVar56);
    }
    else if (bVar31 == 5 || bVar31 == 7) {
      *(short *)pfVar1 = (short)(dVar52 * dVar51);
      *(short *)(pfVar45 + 1) = (short)(dVar52 * dVar56);
    }
    else {
      *pfVar1 = (float)dVar51;
      *(float *)((int)pfVar45 + 6) = (float)dVar56;
    }
    dVar52 = (double)fVar8 * dVar48;
    pfVar1 = (float *)((int)pfVar45 + 6);
    bVar31 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar57 = 1.0;
    }
    else {
      dVar57 = (double)ldexpf(bVar32 & 0x3f);
    }
    if (bVar31 == 4 || bVar31 == 6) {
      *(char *)pfVar1 = (char)(dVar57 * dVar47);
    }
    else if (bVar31 == 5 || bVar31 == 7) {
      *(short *)pfVar1 = (short)(dVar57 * dVar47);
    }
    else {
      *pfVar1 = (float)dVar47;
    }
    dVar38 = (double)fVar11 * dVar55;
    dVar42 = (double)fVar25 * dVar55;
    dVar39 = (double)fVar12 * dVar55;
    dVar47 = (double)fVar15 * dVar50;
    dVar56 = (double)fVar27 * dVar50;
    dVar57 = (double)fVar13 * dVar50;
    lVar6 = ldexpf(0xc3);
    dVar53 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 2));
    dVar58 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 3));
    dVar51 = (double)fVar14 * dVar48;
    dVar36 = (double)fVar26 * dVar48;
    dVar33 = (double)fVar16 * dVar48;
    dVar40 = (double)fVar17 * dVar55;
    dVar43 = (double)fVar28 * dVar55;
    dVar41 = (double)fVar18 * dVar55;
    pfVar2 = (float *)((int)pfVar44 + 2);
    bVar31 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar31 == 4 || bVar31 == 6) {
      dVar48 = (double)(lVar6 * (longlong)(double)*(char *)pfVar2);
      dVar55 = (double)(lVar6 * (longlong)(double)*(char *)((int)pfVar44 + 3));
    }
    else if (bVar31 == 5 || bVar31 == 7) {
      dVar48 = (double)(lVar6 * (longlong)(double)*(short *)pfVar2);
      dVar55 = (double)(lVar6 * (longlong)(double)*(short *)(pfVar44 + 1));
    }
    else {
      dVar48 = (double)*pfVar2;
      dVar55 = (double)*(float *)((int)pfVar44 + 6);
    }
    dVar34 = (double)fVar19 * dVar50;
    dVar37 = (double)fVar29 * dVar50;
    dVar35 = (double)fVar20 * dVar50;
    pfVar44 = (float *)((int)pfVar44 + 6);
    bVar31 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar31 == 4 || bVar31 == 6) {
      dVar50 = (double)(lVar6 * (longlong)(double)*(char *)pfVar44);
    }
    else if (bVar31 == 5 || bVar31 == 7) {
      dVar50 = (double)(lVar6 * (longlong)(double)*(short *)pfVar44);
    }
    else {
      dVar50 = (double)*pfVar44;
    }
    dVar51 = (dVar34 + dVar40 + dVar51 + (double)fVar21) * dVar58 +
             (dVar47 + dVar38 + dVar54 + (double)fVar9) * dVar53;
    dVar56 = (dVar37 + dVar43 + dVar36 + (double)fVar30) * dVar58 +
             (dVar56 + dVar42 + dVar49 + (double)fVar24) * dVar53;
    dVar47 = (dVar35 + dVar41 + dVar33 + (double)fVar22) * dVar58 +
             (dVar57 + dVar39 + dVar52 + (double)fVar10) * dVar53;
    iVar46 = iVar46 + -1;
    param_3 = (float *)((int)param_3 + 2);
  } while (iVar46 != 0);
  pfVar44 = pfVar45 + 2;
  bVar3 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar54 = 1.0;
  }
  else {
    dVar54 = (double)ldexpf(bVar32 & 0x3f);
  }
  if (bVar3 == 4 || bVar3 == 6) {
    *(char *)pfVar44 = (char)(dVar54 * dVar51);
    *(char *)((int)pfVar45 + 9) = (char)(dVar54 * dVar56);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    *(short *)pfVar44 = (short)(dVar54 * dVar51);
    *(short *)((int)pfVar45 + 10) = (short)(dVar54 * dVar56);
  }
  else {
    *pfVar44 = (float)dVar51;
    pfVar45[3] = (float)dVar56;
  }
  pfVar45 = pfVar45 + 3;
  bVar4 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar54 = 1.0;
  }
  else {
    dVar54 = (double)ldexpf(bVar32 & 0x3f);
  }
  if (bVar4 == 4 || bVar4 == 6) {
    *(char *)pfVar45 = (char)(dVar54 * dVar47);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    *(short *)pfVar45 = (short)(dVar54 * dVar47);
  }
  else {
    *pfVar45 = (float)dVar47;
  }
  return;
}

