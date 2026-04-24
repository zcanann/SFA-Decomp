// Function: FUN_8002a074
// Entry: 8002a074
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x8002a1a4) */
/* WARNING: Removing unreachable block (ram,0x8002a154) */
/* WARNING: Removing unreachable block (ram,0x8002a168) */
/* WARNING: Removing unreachable block (ram,0x8002a190) */
/* WARNING: Removing unreachable block (ram,0x8002a184) */
/* WARNING: Removing unreachable block (ram,0x8002a13c) */
/* WARNING: Removing unreachable block (ram,0x8002a130) */
/* WARNING: Removing unreachable block (ram,0x8002a114) */
/* WARNING: Removing unreachable block (ram,0x8002a110) */
/* WARNING: Removing unreachable block (ram,0x8002a108) */
/* WARNING: Removing unreachable block (ram,0x8002a100) */
/* WARNING: Removing unreachable block (ram,0x8002a0fc) */
/* WARNING: Removing unreachable block (ram,0x8002a0f8) */
/* WARNING: Removing unreachable block (ram,0x8002a0f0) */
/* WARNING: Removing unreachable block (ram,0x8002a0e8) */
/* WARNING: Removing unreachable block (ram,0x8002a0e4) */
/* WARNING: Removing unreachable block (ram,0x8002a0dc) */
/* WARNING: Removing unreachable block (ram,0x8002a0d4) */
/* WARNING: Removing unreachable block (ram,0x8002a0d0) */
/* WARNING: Removing unreachable block (ram,0x8002a0cc) */
/* WARNING: Removing unreachable block (ram,0x8002a0c0) */
/* WARNING: Removing unreachable block (ram,0x8002a0b8) */

void FUN_8002a074(float *param_1,float *param_2,float *param_3,float *param_4,int param_5,
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
  byte bVar25;
  byte bVar26;
  double dVar27;
  double dVar28;
  double dVar29;
  double dVar30;
  double dVar31;
  double dVar32;
  double dVar33;
  double dVar34;
  float *pfVar35;
  float *pfVar36;
  int iVar37;
  uint unaff_GQR7;
  double dVar38;
  double dVar39;
  double dVar40;
  double dVar41;
  double dVar42;
  double dVar43;
  double dVar44;
  double dVar45;
  double dVar46;
  double dVar47;
  double dVar48;
  double dVar49;
  double dVar50;
  double dVar51;
  double dVar52;
  
  iVar37 = param_6 + -1;
  fVar7 = *param_1;
  fVar19 = param_1[1];
  fVar8 = param_1[2];
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
    dVar38 = (double)(lVar6 * (longlong)(double)*(char *)param_4);
    dVar47 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_4 + 1));
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar38 = (double)(lVar6 * (longlong)(double)*(short *)param_4);
    dVar47 = (double)(lVar6 * (longlong)(double)*(short *)((int)param_4 + 2));
  }
  else {
    dVar38 = (double)*param_4;
    dVar47 = (double)param_4[1];
  }
  pfVar35 = (float *)((int)param_4 + 2);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar40 = (double)(lVar6 * (longlong)(double)*(char *)pfVar35);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar40 = (double)(lVar6 * (longlong)(double)*(short *)pfVar35);
  }
  else {
    dVar40 = (double)*pfVar35;
  }
  lVar6 = ldexpf(0xc3);
  dVar45 = (double)(lVar6 * (longlong)(double)*(char *)param_3);
  dVar51 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 1));
  fVar9 = param_1[3];
  fVar20 = param_1[4];
  fVar10 = param_1[5];
  fVar11 = param_1[8];
  fVar12 = *param_2;
  fVar21 = param_2[1];
  fVar13 = param_1[6];
  fVar22 = param_1[7];
  fVar14 = param_2[2];
  fVar15 = param_2[3];
  fVar23 = param_2[4];
  fVar16 = param_2[5];
  fVar17 = param_2[6];
  fVar24 = param_2[7];
  fVar18 = param_2[8];
  pfVar35 = (float *)((int)param_4 + 3);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar39 = (double)(lVar6 * (longlong)(double)*(char *)pfVar35);
    dVar48 = (double)(lVar6 * (longlong)(double)*(char *)(param_4 + 1));
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar39 = (double)(lVar6 * (longlong)(double)*(short *)pfVar35);
    dVar48 = (double)(lVar6 * (longlong)(double)*(short *)((int)param_4 + 5));
  }
  else {
    dVar39 = (double)*pfVar35;
    dVar48 = (double)*(float *)((int)param_4 + 7);
  }
  pfVar35 = (float *)((int)param_4 + 5);
  bVar4 = bVar3 & 7;
  if ((unaff_GQR7 & 0x3f000000) == 0) {
    lVar6 = 0x3ff0000000000000;
  }
  else {
    lVar6 = ldexpf(-(bVar5 & 0x3f));
  }
  if (bVar4 == 4 || bVar4 == 6) {
    dVar41 = (double)(lVar6 * (longlong)(double)*(char *)pfVar35);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    dVar41 = (double)(lVar6 * (longlong)(double)*(short *)pfVar35);
  }
  else {
    dVar41 = (double)*pfVar35;
  }
  dVar42 = ((double)fVar17 * dVar40 + (double)fVar15 * dVar47 + (double)fVar12 * dVar38) * dVar51 +
           ((double)fVar13 * dVar40 + (double)fVar9 * dVar47 + (double)fVar7 * dVar38) * dVar45;
  dVar49 = ((double)fVar24 * dVar40 + (double)fVar23 * dVar47 + (double)fVar21 * dVar38) * dVar51 +
           ((double)fVar22 * dVar40 + (double)fVar20 * dVar47 + (double)fVar19 * dVar38) * dVar45;
  dVar38 = ((double)fVar18 * dVar40 + (double)fVar16 * dVar47 + (double)fVar14 * dVar38) * dVar51 +
           ((double)fVar11 * dVar40 + (double)fVar10 * dVar47 + (double)fVar8 * dVar38) * dVar45;
  pfVar1 = (float *)(param_5 + -1);
  do {
    pfVar36 = pfVar1;
    dVar47 = (double)fVar7 * dVar39;
    dVar40 = (double)fVar19 * dVar39;
    pfVar1 = (float *)((int)pfVar36 + 1);
    bVar4 = (byte)unaff_GQR7;
    bVar25 = bVar4 & 7;
    bVar26 = (byte)(unaff_GQR7 >> 8);
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar45 = 1.0;
    }
    else {
      dVar45 = (double)ldexpf(bVar26 & 0x3f);
    }
    if (bVar25 == 4 || bVar25 == 6) {
      *(char *)pfVar1 = (char)(dVar45 * dVar42);
      *(char *)((int)pfVar36 + 2) = (char)(dVar45 * dVar49);
    }
    else if (bVar25 == 5 || bVar25 == 7) {
      *(short *)pfVar1 = (short)(dVar45 * dVar42);
      *(short *)((int)pfVar36 + 3) = (short)(dVar45 * dVar49);
    }
    else {
      *pfVar1 = (float)dVar42;
      *(float *)((int)pfVar36 + 5) = (float)dVar49;
    }
    dVar45 = (double)fVar8 * dVar39;
    pfVar1 = (float *)((int)pfVar36 + 3);
    bVar25 = bVar4 & 7;
    if ((unaff_GQR7 & 0x3f00) == 0) {
      dVar51 = 1.0;
    }
    else {
      dVar51 = (double)ldexpf(bVar26 & 0x3f);
    }
    if (bVar25 == 4 || bVar25 == 6) {
      *(char *)pfVar1 = (char)(dVar51 * dVar38);
    }
    else if (bVar25 == 5 || bVar25 == 7) {
      *(short *)pfVar1 = (short)(dVar51 * dVar38);
    }
    else {
      *pfVar1 = (float)dVar38;
    }
    dVar42 = (double)fVar9 * dVar48;
    dVar33 = (double)fVar20 * dVar48;
    dVar30 = (double)fVar10 * dVar48;
    dVar38 = (double)fVar13 * dVar41;
    dVar49 = (double)fVar22 * dVar41;
    dVar51 = (double)fVar11 * dVar41;
    lVar6 = ldexpf(0xc3);
    dVar46 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 2));
    dVar52 = (double)(lVar6 * (longlong)(double)*(char *)((int)param_3 + 3));
    dVar43 = (double)fVar12 * dVar39;
    dVar50 = (double)fVar21 * dVar39;
    dVar44 = (double)fVar14 * dVar39;
    dVar31 = (double)fVar15 * dVar48;
    dVar34 = (double)fVar23 * dVar48;
    dVar32 = (double)fVar16 * dVar48;
    pfVar2 = (float *)((int)pfVar35 + 1);
    bVar25 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar25 == 4 || bVar25 == 6) {
      dVar39 = (double)(lVar6 * (longlong)(double)*(char *)pfVar2);
      dVar48 = (double)(lVar6 * (longlong)(double)*(char *)((int)pfVar35 + 2));
    }
    else if (bVar25 == 5 || bVar25 == 7) {
      dVar39 = (double)(lVar6 * (longlong)(double)*(short *)pfVar2);
      dVar48 = (double)(lVar6 * (longlong)(double)*(short *)((int)pfVar35 + 3));
    }
    else {
      dVar39 = (double)*pfVar2;
      dVar48 = (double)*(float *)((int)pfVar35 + 5);
    }
    dVar27 = (double)fVar17 * dVar41;
    dVar29 = (double)fVar24 * dVar41;
    dVar28 = (double)fVar18 * dVar41;
    pfVar35 = (float *)((int)pfVar35 + 3);
    bVar25 = bVar3 & 7;
    if ((unaff_GQR7 & 0x3f000000) == 0) {
      lVar6 = 0x3ff0000000000000;
    }
    else {
      lVar6 = ldexpf(-(bVar5 & 0x3f));
    }
    if (bVar25 == 4 || bVar25 == 6) {
      dVar41 = (double)(lVar6 * (longlong)(double)*(char *)pfVar35);
    }
    else if (bVar25 == 5 || bVar25 == 7) {
      dVar41 = (double)(lVar6 * (longlong)(double)*(short *)pfVar35);
    }
    else {
      dVar41 = (double)*pfVar35;
    }
    dVar42 = (dVar27 + dVar31 + dVar43) * dVar52 + (dVar38 + dVar42 + dVar47) * dVar46;
    dVar49 = (dVar29 + dVar34 + dVar50) * dVar52 + (dVar49 + dVar33 + dVar40) * dVar46;
    dVar38 = (dVar28 + dVar32 + dVar44) * dVar52 + (dVar51 + dVar30 + dVar45) * dVar46;
    iVar37 = iVar37 + -1;
    param_3 = (float *)((int)param_3 + 2);
  } while (iVar37 != 0);
  pfVar35 = pfVar36 + 1;
  bVar3 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar47 = 1.0;
  }
  else {
    dVar47 = (double)ldexpf(bVar26 & 0x3f);
  }
  if (bVar3 == 4 || bVar3 == 6) {
    *(char *)pfVar35 = (char)(dVar47 * dVar42);
    *(char *)((int)pfVar36 + 5) = (char)(dVar47 * dVar49);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    *(short *)pfVar35 = (short)(dVar47 * dVar42);
    *(short *)((int)pfVar36 + 6) = (short)(dVar47 * dVar49);
  }
  else {
    *pfVar35 = (float)dVar42;
    pfVar36[2] = (float)dVar49;
  }
  pfVar36 = (float *)((int)pfVar36 + 6);
  bVar4 = bVar4 & 7;
  if ((unaff_GQR7 & 0x3f00) == 0) {
    dVar47 = 1.0;
  }
  else {
    dVar47 = (double)ldexpf(bVar26 & 0x3f);
  }
  if (bVar4 == 4 || bVar4 == 6) {
    *(char *)pfVar36 = (char)(dVar47 * dVar38);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    *(short *)pfVar36 = (short)(dVar47 * dVar38);
  }
  else {
    *pfVar36 = (float)dVar38;
  }
  return;
}

