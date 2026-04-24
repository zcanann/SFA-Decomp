// Function: FUN_80006e34
// Entry: 80006e34
// Size: 1684 bytes

/* WARNING: Removing unreachable block (ram,0x80007e50) */
/* WARNING: Removing unreachable block (ram,0x80007e90) */
/* WARNING: Removing unreachable block (ram,0x80007e88) */
/* WARNING: Removing unreachable block (ram,0x80007e80) */
/* WARNING: Removing unreachable block (ram,0x80007e5c) */
/* WARNING: Removing unreachable block (ram,0x80007e54) */
/* WARNING: Removing unreachable block (ram,0x80007e4c) */
/* WARNING: Removing unreachable block (ram,0x80007d7c) */
/* WARNING: Removing unreachable block (ram,0x800072a0) */
/* WARNING: Removing unreachable block (ram,0x80007170) */
/* WARNING: Removing unreachable block (ram,0x80007160) */
/* WARNING: Removing unreachable block (ram,0x80007274) */
/* WARNING: Removing unreachable block (ram,0x80007150) */
/* WARNING: Removing unreachable block (ram,0x80007e58) */
/* WARNING: Removing unreachable block (ram,0x80007e60) */
/* WARNING: Removing unreachable block (ram,0x80007e8c) */
/* WARNING: Removing unreachable block (ram,0x80007e94) */
/* WARNING: Removing unreachable block (ram,0x80007248) */
/* WARNING: Removing unreachable block (ram,0x80007e84) */

void FUN_80006e34(int param_1,float *param_2,undefined4 param_3,undefined4 param_4,int param_5,
                 undefined4 param_6,uint param_7,uint param_8,undefined4 param_9,float param_10)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  short sVar11;
  short sVar12;
  byte bVar13;
  byte bVar14;
  byte bVar15;
  longlong lVar16;
  byte bVar17;
  byte bVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  int iVar23;
  int unaff_r2;
  int iVar24;
  undefined2 *in_r12;
  int unaff_r13;
  uint uVar25;
  short sVar27;
  float *pfVar26;
  int unaff_r16;
  float *pfVar28;
  uint uVar29;
  int iVar30;
  int iVar31;
  int iVar32;
  uint uVar33;
  undefined2 *puVar34;
  int iVar35;
  byte *pbVar36;
  int iVar37;
  int unaff_r31;
  bool bVar38;
  uint unaff_GQR0;
  uint unaff_GQR3;
  uint unaff_GQR5;
  double dVar39;
  double dVar40;
  double in_f6;
  double in_f7;
  double in_f8;
  double in_f9;
  double dVar41;
  double in_f10;
  double dVar42;
  double in_f11;
  double dVar43;
  double in_f12;
  double in_f13;
  double dVar44;
  double in_f14;
  double in_f15;
  double dVar45;
  double in_f16;
  double in_f17;
  double in_f18;
  double in_f19;
  double dVar46;
  double dVar47;
  double dVar48;
  double dVar49;
  double dVar50;
  double in_f28;
  double dVar51;
  double in_f30;
  double dVar52;
  double dVar53;
  double dVar54;
  double dVar55;
  double dVar56;
  double dVar57;
  double dVar58;
  double in_ps14_1;
  double dVar59;
  double in_ps15_1;
  double dVar60;
  double in_ps16_1;
  double in_ps17_1;
  
  if ((param_8 & 0x20) != 0) {
    *in_r12 = *(undefined2 *)(unaff_r13 + -0x6a1c);
    in_r12[1] = *(undefined2 *)(unaff_r13 + -0x6a1a);
    in_r12[2] = *(undefined2 *)(unaff_r13 + -0x6a18);
  }
  iVar32 = *(int *)(unaff_r13 + -0x6a20);
  iVar31 = unaff_r31;
  if (((param_8 & 0xc) != 0) && (iVar31 = param_1 + 0x1c, (param_8 & 8) != 0)) {
    iVar31 = param_1 + 0x22;
  }
  dVar52 = (double)*(float *)(unaff_r2 + -0x7ff0);
  dVar51 = (double)*(float *)(unaff_r2 + -0x7fec);
  dVar50 = (double)(float)(dVar52 - in_f28);
  iVar30 = param_5 * 0x1c + iVar32;
  do {
    puVar34 = in_r12 + (uint)*(byte *)(iVar32 + 3) * 0x20;
    iVar37 = (uint)*(byte *)(iVar32 + 2) * 0x40;
    iVar35 = unaff_r31 + iVar37;
    iVar37 = iVar31 + iVar37;
    iVar24 = 2;
    if ((param_8 & 0xf) != 0) {
      uVar29 = *(byte *)(iVar32 + 1) & 0x7f;
      iVar23 = uVar29 * 0x40;
      iVar37 = iVar31 + iVar23;
      if ((param_8 & 3) != 0) {
        if ((param_8 & 1) == 0) {
          puVar34 = in_r12 + uVar29 * 0x20;
        }
        else {
          iVar35 = unaff_r31 + iVar23;
        }
      }
    }
    do {
      uVar29 = (uint)(ushort)puVar34[6];
      if (uVar29 == 0) {
        uVar29 = 0x400;
      }
      uVar25 = (uint)*(ushort *)(iVar35 + 0xc);
      if (uVar25 == 0) {
        uVar25 = 0x400;
      }
      uVar29 = (uVar29 - uVar25) * unaff_r16;
      bVar38 = (int)uVar29 < 0 && (uVar29 & 0x3fff) != 0;
      *(short *)(iVar37 + 0xc) = (short)((int)uVar29 >> 0xe) + (short)uVar25;
      sVar27 = *(short *)(iVar35 + 0x18);
      iVar35 = iVar35 + 2;
      if ((param_8 & 0x10) == 0) {
        uVar29 = ((int)(short)puVar34[0xc] - (int)sVar27) * unaff_r16;
        bVar38 = (int)uVar29 < 0 && (uVar29 & 0x3fff) != 0;
        sVar27 = sVar27 + (short)((int)uVar29 >> 0xe);
      }
      *(short *)(iVar37 + 0x18) = sVar27;
      iVar37 = iVar37 + 2;
      bVar1 = iVar24 != 0;
      iVar24 = iVar24 + (bVar38 - 1);
      puVar34 = puVar34 + 1;
    } while (bVar1);
    iVar32 = iVar32 + 0x1c;
  } while (iVar32 != iVar30);
  iVar30 = *(int *)(unaff_r13 + -0x6a20);
  uVar29 = param_7;
  iVar32 = param_5;
  do {
    while( true ) {
      while( true ) {
        iVar37 = (uint)*(byte *)(iVar30 + 2) << 6;
        if ((param_8 & 1) == 0) {
          FUN_800072c4();
          in_f14 = (double)(float)(in_f7 * in_f18);
          fVar7 = (float)(in_f10 + in_f11);
          in_f15 = (double)(float)(in_f8 * in_f19);
          fVar8 = (float)(in_f12 - in_f13);
          in_f16 = (double)(float)(in_f6 * in_f19);
          fVar9 = (float)(in_f14 + in_f15);
          in_f17 = (double)(float)(in_f9 * in_f18);
          fVar10 = (float)(in_f16 - in_f17);
          in_ps14_1 = in_f14;
          in_ps15_1 = in_f15;
          in_ps16_1 = in_f16;
          in_ps17_1 = in_f17;
        }
        else {
          iVar37 = (*(byte *)(iVar30 + 1) & 0x7f) * 0x40;
          pfVar28 = (float *)(iVar37 + param_1);
          fVar7 = *pfVar28;
          fVar8 = pfVar28[1];
          fVar9 = pfVar28[2];
          fVar10 = pfVar28[3];
        }
        dVar49 = (double)fVar10;
        dVar48 = (double)fVar9;
        dVar47 = (double)fVar8;
        dVar46 = (double)fVar7;
        iVar37 = iVar31 + iVar37;
        if ((param_8 & 2) == 0) {
          FUN_800072c4();
          in_f14 = (double)(float)(in_f7 * in_f18);
          fVar7 = (float)(in_f10 + in_f11);
          in_f15 = (double)(float)(in_f8 * in_f19);
          fVar8 = (float)(in_f12 - in_f13);
          in_f16 = (double)(float)(in_f6 * in_f19);
          fVar9 = (float)(in_f14 + in_f15);
          in_f17 = (double)(float)(in_f9 * in_f18);
          fVar10 = (float)(in_f16 - in_f17);
          in_ps14_1 = in_f14;
          in_ps15_1 = in_f15;
          in_ps16_1 = in_f16;
          in_ps17_1 = in_f17;
        }
        else {
          iVar24 = (*(byte *)(iVar30 + 1) & 0x7f) * 0x40 + param_1;
          fVar7 = *(float *)(iVar24 + 0x10);
          fVar8 = *(float *)(iVar24 + 0x14);
          fVar9 = *(float *)(iVar24 + 0x18);
          fVar10 = *(float *)(iVar24 + 0x1c);
        }
        in_f7 = (double)fVar10;
        in_f6 = (double)fVar9;
        dVar40 = (double)fVar8;
        dVar39 = (double)fVar7;
        in_f11 = (double)(float)(dVar47 * dVar40);
        in_f12 = (double)(float)(dVar48 * in_f6);
        in_f13 = (double)(float)(dVar49 * in_f7);
        in_f10 = (double)(float)((double)(float)((double)(float)((double)(float)(dVar46 * dVar39) +
                                                                in_f11) + in_f12) + in_f13);
        if (in_f10 < in_f30) {
          dVar39 = (double)(float)(in_f30 - dVar39);
          dVar40 = (double)(float)(in_f30 - dVar40);
          in_f6 = (double)(float)(in_f30 - in_f6);
          in_f7 = (double)(float)(in_f30 - in_f7);
        }
        uVar25 = (int)*(char *)(iVar30 + 1) & param_7;
        if (-1 < (int)uVar25) break;
        iVar32 = iVar32 + -1;
        iVar30 = iVar30 + 0x1c;
        if (iVar32 == 0) goto LAB_80007d74;
      }
      fVar8 = (float)(dVar46 * dVar50) + (float)(dVar39 * in_f28);
      in_f10 = (double)fVar8;
      in_f6 = (double)(float)(in_f6 * in_f28);
      fVar10 = (float)(dVar47 * dVar50) + (float)(dVar40 * in_f28);
      in_f11 = (double)fVar10;
      in_f7 = (double)(float)(in_f7 * in_f28);
      fVar7 = (float)((double)(float)(dVar48 * dVar50) + in_f6);
      in_f12 = (double)fVar7;
      fVar9 = (float)((double)(float)(dVar49 * dVar50) + in_f7);
      in_f13 = (double)fVar9;
      if ((param_8 & 0xc) == 0) break;
      iVar37 = param_1;
      if ((param_8 & 8) != 0) {
        iVar37 = param_1 + 0x10;
      }
      pfVar28 = (float *)((*(byte *)(iVar30 + 1) & 0x7f) * 0x40 + iVar37);
      *pfVar28 = fVar8;
      pfVar28[1] = fVar10;
      pfVar28[2] = fVar7;
      pfVar28[3] = fVar9;
      iVar32 = iVar32 + -1;
      iVar30 = iVar30 + 0x1c;
      if (iVar32 == 0) {
        return;
      }
    }
    dVar46 = (double)(float)(in_f12 * dVar51);
    pfVar26 = (float *)(*(int *)(unaff_r13 + -0x8000) + (uVar25 & 0x7f) * 0x40);
    dVar47 = (double)*(float *)(unaff_r2 + -0x7fe8);
    pfVar28 = (float *)(iVar37 + 0x18);
    bVar13 = (byte)(unaff_GQR5 >> 0x10);
    bVar14 = bVar13 & 7;
    bVar15 = (byte)(unaff_GQR5 >> 0x18);
    if ((unaff_GQR5 & 0x3f000000) == 0) {
      lVar16 = 0x3ff0000000000000;
    }
    else {
      lVar16 = ldexpf(-(bVar15 & 0x3f));
    }
    if (bVar14 == 4 || bVar14 == 6) {
      dVar48 = (double)(lVar16 * (longlong)(double)*(char *)pfVar28);
    }
    else if (bVar14 == 5 || bVar14 == 7) {
      dVar48 = (double)(lVar16 * (longlong)(double)*(short *)pfVar28);
    }
    else {
      dVar48 = (double)*pfVar28;
    }
    pfVar28 = (float *)(iVar37 + 0x1a);
    bVar14 = bVar13 & 7;
    if ((unaff_GQR5 & 0x3f000000) == 0) {
      lVar16 = 0x3ff0000000000000;
    }
    else {
      lVar16 = ldexpf(-(bVar15 & 0x3f));
    }
    if (bVar14 == 4 || bVar14 == 6) {
      dVar49 = (double)(lVar16 * (longlong)(double)*(char *)pfVar28);
    }
    else if (bVar14 == 5 || bVar14 == 7) {
      dVar49 = (double)(lVar16 * (longlong)(double)*(short *)pfVar28);
    }
    else {
      dVar49 = (double)*pfVar28;
    }
    fVar7 = *(float *)(iVar30 + 8);
    pfVar28 = (float *)(iVar37 + 0x1c);
    bVar13 = bVar13 & 7;
    if ((unaff_GQR5 & 0x3f000000) == 0) {
      lVar16 = 0x3ff0000000000000;
    }
    else {
      lVar16 = ldexpf(-(bVar15 & 0x3f));
    }
    if (bVar13 == 4 || bVar13 == 6) {
      dVar39 = (double)(lVar16 * (longlong)(double)*(char *)pfVar28);
    }
    else if (bVar13 == 5 || bVar13 == 7) {
      dVar39 = (double)(lVar16 * (longlong)(double)*(short *)pfVar28);
    }
    else {
      dVar39 = (double)*pfVar28;
    }
    fVar9 = *(float *)(iVar30 + 0xc);
    sVar27 = *(short *)(iVar37 + 0xc);
    sVar11 = *(short *)(iVar37 + 0xe);
    sVar12 = *(short *)(iVar37 + 0x10);
    pfVar26[3] = (float)(dVar48 * dVar47) + *(float *)(iVar30 + 4);
    dVar48 = (double)(float)(in_f13 * dVar51);
    dVar40 = (double)(float)(in_f10 * (double)(float)(in_f11 * dVar51));
    pfVar26[0xb] = (float)(dVar39 * dVar47) + fVar9;
    pfVar26[7] = (float)(dVar49 * dVar47) + fVar7;
    dVar47 = in_f10 * dVar48;
    in_f6 = (double)(float)(in_f11 * (double)(float)(in_f11 * dVar51));
    in_f7 = (double)(float)(in_f11 * dVar46);
    in_f8 = (double)(float)(in_f11 * dVar48);
    fVar7 = (float)(in_f7 + (double)(float)dVar47);
    in_f17 = (double)(float)(in_f13 * dVar48);
    fVar10 = (float)(in_f8 - (double)(float)(in_f10 * dVar46));
    in_f15 = (double)(float)(in_f12 * dVar46);
    fVar9 = (float)(in_f8 + (double)(float)(in_f10 * dVar46));
    in_f16 = (double)(float)(in_f12 * dVar48);
    fVar2 = (float)(dVar52 - (double)(float)(in_f15 + in_f17));
    in_f19 = (double)fVar2;
    fVar3 = (float)(in_f16 - dVar40);
    fVar4 = (float)(dVar52 - (double)(float)(in_f6 + in_f15));
    in_f10 = (double)fVar4;
    fVar8 = (float)(in_f16 + dVar40);
    fVar5 = (float)(in_f7 - (double)(float)dVar47);
    fVar6 = (float)(dVar52 - (double)(float)(in_f6 + in_f17));
    dVar46 = (double)*(float *)(unaff_r2 + -0x7fe4);
    bVar13 = (byte)(unaff_GQR3 >> 0x10);
    bVar14 = (byte)(unaff_GQR3 >> 0x18);
    if (sVar27 == 0) {
      *pfVar26 = fVar2;
      pfVar26[1] = fVar7;
      pfVar26[2] = fVar10;
      if (sVar11 != 0) goto LAB_80007270;
LAB_80007210:
      pfVar26[1] = fVar5;
      pfVar26[5] = fVar6;
      pfVar26[9] = fVar8;
      if (sVar12 != 0) goto LAB_8000729c;
LAB_80007224:
      pfVar26[2] = fVar9;
      pfVar26[6] = fVar3;
      pfVar26[10] = fVar4;
    }
    else {
      param_10 = (float)CONCAT22(sVar27,param_10._2_2_);
      fVar2 = param_10;
      bVar15 = bVar13 & 7;
      if ((unaff_GQR3 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar14 & 0x3f));
      }
      if (bVar15 == 4 || bVar15 == 6) {
        param_10._0_1_ = (char)((ushort)sVar27 >> 8);
        dVar47 = (double)(lVar16 * (longlong)(double)param_10._0_1_);
      }
      else if (bVar15 == 5 || bVar15 == 7) {
        dVar47 = (double)(lVar16 * (longlong)(double)sVar27);
      }
      else {
        dVar47 = (double)param_10;
      }
      dVar48 = (double)(float)(dVar47 * dVar46);
      dVar47 = in_f19 * dVar48;
      in_f19 = (double)(float)dVar47;
      *pfVar26 = (float)dVar47;
      pfVar26[4] = (float)((double)fVar7 * dVar48);
      pfVar26[8] = (float)((double)fVar10 * dVar48);
      param_10 = fVar2;
      if (sVar11 == 0) goto LAB_80007210;
LAB_80007270:
      param_10 = (float)CONCAT22(sVar11,param_10._2_2_);
      fVar7 = param_10;
      bVar15 = bVar13 & 7;
      if ((unaff_GQR3 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar14 & 0x3f));
      }
      if (bVar15 == 4 || bVar15 == 6) {
        param_10._0_1_ = (char)((ushort)sVar11 >> 8);
        dVar47 = (double)(lVar16 * (longlong)(double)param_10._0_1_);
      }
      else if (bVar15 == 5 || bVar15 == 7) {
        dVar47 = (double)(lVar16 * (longlong)(double)sVar11);
      }
      else {
        dVar47 = (double)param_10;
      }
      fVar10 = (float)(dVar47 * dVar46);
      pfVar26[1] = fVar5 * fVar10;
      pfVar26[5] = fVar6 * fVar10;
      pfVar26[9] = fVar8 * fVar10;
      param_10 = fVar7;
      if (sVar12 == 0) goto LAB_80007224;
LAB_8000729c:
      param_10 = (float)CONCAT22(sVar12,param_10._2_2_);
      fVar7 = param_10;
      bVar13 = bVar13 & 7;
      if ((unaff_GQR3 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar14 & 0x3f));
      }
      if (bVar13 == 4 || bVar13 == 6) {
        param_10._0_1_ = (char)((ushort)sVar12 >> 8);
        dVar47 = (double)(lVar16 * (longlong)(double)param_10._0_1_);
      }
      else if (bVar13 == 5 || bVar13 == 7) {
        dVar47 = (double)(lVar16 * (longlong)(double)sVar12);
      }
      else {
        dVar47 = (double)param_10;
      }
      dVar46 = (double)(float)(dVar47 * dVar46);
      pfVar26[2] = (float)((double)fVar9 * dVar46);
      pfVar26[6] = (float)((double)fVar3 * dVar46);
      dVar46 = in_f10 * dVar46;
      in_f10 = (double)(float)dVar46;
      pfVar26[10] = (float)dVar46;
      param_10 = fVar7;
    }
    iVar32 = iVar32 + -1;
    iVar30 = iVar30 + 0x1c;
    in_ps15_1 = in_f15;
    in_ps16_1 = in_f16;
    in_ps17_1 = in_f17;
  } while (iVar32 != 0);
LAB_80007d74:
  bVar13 = (byte)(unaff_GQR0 >> 0x10);
  bVar14 = bVar13 & 7;
  bVar15 = (byte)(unaff_GQR0 >> 0x18);
  if ((unaff_GQR0 & 0x3f000000) == 0) {
    lVar16 = 0x3ff0000000000000;
  }
  else {
    lVar16 = ldexpf(-(bVar15 & 0x3f));
  }
  if (bVar14 == 4 || bVar14 == 6) {
    dVar50 = (double)(lVar16 * (longlong)(double)DAT_803df180._0_1_);
    dVar51 = (double)(lVar16 * (longlong)(double)DAT_803df180._1_1_);
  }
  else if (bVar14 == 5 || bVar14 == 7) {
    dVar50 = (double)(lVar16 * (longlong)(double)DAT_803df180._0_2_);
    dVar51 = (double)(lVar16 * (longlong)(double)DAT_803df180._2_2_);
  }
  else {
    dVar50 = (double)DAT_803df180;
    dVar51 = (double)DAT_803df184;
  }
  if ((param_8 & 0xc) == 0) {
    iVar31 = *(int *)(unaff_r13 + -0x8000);
    pbVar36 = *(byte **)(unaff_r13 + -0x6a20);
    uVar25 = (int)(char)pbVar36[1] & 0x7f;
    pfVar28 = (float *)(uVar25 * 0x40 + iVar31);
    if (-1 < (int)((int)(char)pbVar36[1] & uVar29)) goto LAB_80007e4c;
    uVar33 = 0xfffffffb;
    dVar52 = in_f12;
    dVar46 = in_f13;
    while (param_5 = param_5 + -1, param_5 != 0) {
      while( true ) {
        pbVar36 = pbVar36 + 0x1c;
        uVar25 = (int)(char)pbVar36[1] & uVar29;
        if (-1 < (int)uVar25) break;
        uVar33 = 0xffffffff;
        param_5 = param_5 + -1;
        if (param_5 == 0) {
          return;
        }
      }
      pfVar28 = (float *)(uVar25 * 0x40 + iVar31);
      if (*pbVar36 != uVar33) {
        param_2 = (float *)((uint)*pbVar36 * 0x40 + iVar31);
LAB_80007e4c:
        bVar14 = bVar13 & 7;
        if ((unaff_GQR0 & 0x3f000000) == 0) {
          lVar16 = 0x3ff0000000000000;
        }
        else {
          lVar16 = ldexpf(-(bVar15 & 0x3f));
        }
        if (bVar14 == 4 || bVar14 == 6) {
          in_f12 = (double)(lVar16 * (longlong)(double)*(char *)param_2);
          dVar52 = (double)(lVar16 * (longlong)(double)*(char *)((int)param_2 + 1));
        }
        else if (bVar14 == 5 || bVar14 == 7) {
          in_f12 = (double)(lVar16 * (longlong)(double)*(short *)param_2);
          dVar52 = (double)(lVar16 * (longlong)(double)*(short *)((int)param_2 + 2));
        }
        else {
          in_f12 = (double)*param_2;
          dVar52 = (double)param_2[1];
        }
        pfVar26 = param_2 + 2;
        bVar14 = bVar13 & 7;
        if ((unaff_GQR0 & 0x3f000000) == 0) {
          lVar16 = 0x3ff0000000000000;
        }
        else {
          lVar16 = ldexpf(-(bVar15 & 0x3f));
        }
        if (bVar14 == 4 || bVar14 == 6) {
          in_f13 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
          dVar46 = (double)(lVar16 * (longlong)(double)*(char *)((int)param_2 + 9));
        }
        else if (bVar14 == 5 || bVar14 == 7) {
          in_f13 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
          dVar46 = (double)(lVar16 * (longlong)(double)*(short *)((int)param_2 + 10));
        }
        else {
          in_f13 = (double)*pfVar26;
          dVar46 = (double)param_2[3];
        }
        pfVar26 = param_2 + 4;
        bVar14 = bVar13 & 7;
        if ((unaff_GQR0 & 0x3f000000) == 0) {
          lVar16 = 0x3ff0000000000000;
        }
        else {
          lVar16 = ldexpf(-(bVar15 & 0x3f));
        }
        if (bVar14 == 4 || bVar14 == 6) {
          in_f14 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
          in_ps14_1 = (double)(lVar16 * (longlong)(double)*(char *)((int)param_2 + 0x11));
        }
        else if (bVar14 == 5 || bVar14 == 7) {
          in_f14 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
          in_ps14_1 = (double)(lVar16 * (longlong)(double)*(short *)((int)param_2 + 0x12));
        }
        else {
          in_f14 = (double)*pfVar26;
          in_ps14_1 = (double)param_2[5];
        }
        pfVar26 = param_2 + 6;
        bVar14 = bVar13 & 7;
        if ((unaff_GQR0 & 0x3f000000) == 0) {
          lVar16 = 0x3ff0000000000000;
        }
        else {
          lVar16 = ldexpf(-(bVar15 & 0x3f));
        }
        if (bVar14 == 4 || bVar14 == 6) {
          in_f15 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
          in_ps15_1 = (double)(lVar16 * (longlong)(double)*(char *)((int)param_2 + 0x19));
        }
        else if (bVar14 == 5 || bVar14 == 7) {
          in_f15 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
          in_ps15_1 = (double)(lVar16 * (longlong)(double)*(short *)((int)param_2 + 0x1a));
        }
        else {
          in_f15 = (double)*pfVar26;
          in_ps15_1 = (double)param_2[7];
        }
        pfVar26 = param_2 + 8;
        bVar14 = bVar13 & 7;
        if ((unaff_GQR0 & 0x3f000000) == 0) {
          lVar16 = 0x3ff0000000000000;
        }
        else {
          lVar16 = ldexpf(-(bVar15 & 0x3f));
        }
        if (bVar14 == 4 || bVar14 == 6) {
          in_f16 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
          in_ps16_1 = (double)(lVar16 * (longlong)(double)*(char *)((int)param_2 + 0x21));
        }
        else if (bVar14 == 5 || bVar14 == 7) {
          in_f16 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
          in_ps16_1 = (double)(lVar16 * (longlong)(double)*(short *)((int)param_2 + 0x22));
        }
        else {
          in_f16 = (double)*pfVar26;
          in_ps16_1 = (double)param_2[9];
        }
        pfVar26 = param_2 + 10;
        bVar14 = bVar13 & 7;
        if ((unaff_GQR0 & 0x3f000000) == 0) {
          lVar16 = 0x3ff0000000000000;
        }
        else {
          lVar16 = ldexpf(-(bVar15 & 0x3f));
        }
        if (bVar14 == 4 || bVar14 == 6) {
          in_f17 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
          in_ps17_1 = (double)(lVar16 * (longlong)(double)*(char *)((int)param_2 + 0x29));
        }
        else if (bVar14 == 5 || bVar14 == 7) {
          in_f17 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
          in_ps17_1 = (double)(lVar16 * (longlong)(double)*(short *)((int)param_2 + 0x2a));
        }
        else {
          in_f17 = (double)*pfVar26;
          in_ps17_1 = (double)param_2[0xb];
        }
      }
      bVar14 = bVar13 & 7;
      if ((unaff_GQR0 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar15 & 0x3f));
      }
      if (bVar14 == 4 || bVar14 == 6) {
        dVar47 = (double)(lVar16 * (longlong)(double)*(char *)pfVar28);
        dVar48 = (double)(lVar16 * (longlong)(double)*(char *)((int)pfVar28 + 1));
      }
      else if (bVar14 == 5 || bVar14 == 7) {
        dVar47 = (double)(lVar16 * (longlong)(double)*(short *)pfVar28);
        dVar48 = (double)(lVar16 * (longlong)(double)*(short *)((int)pfVar28 + 2));
      }
      else {
        dVar47 = (double)*pfVar28;
        dVar48 = (double)pfVar28[1];
      }
      pfVar26 = pfVar28 + 2;
      bVar14 = bVar13 & 7;
      if ((unaff_GQR0 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar15 & 0x3f));
      }
      if (bVar14 == 4 || bVar14 == 6) {
        dVar49 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
        dVar39 = (double)(lVar16 * (longlong)(double)*(char *)((int)pfVar28 + 9));
      }
      else if (bVar14 == 5 || bVar14 == 7) {
        dVar49 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
        dVar39 = (double)(lVar16 * (longlong)(double)*(short *)((int)pfVar28 + 10));
      }
      else {
        dVar49 = (double)*pfVar26;
        dVar39 = (double)pfVar28[3];
      }
      pfVar26 = pfVar28 + 4;
      bVar14 = bVar13 & 7;
      if ((unaff_GQR0 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar15 & 0x3f));
      }
      if (bVar14 == 4 || bVar14 == 6) {
        dVar40 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
        dVar53 = (double)(lVar16 * (longlong)(double)*(char *)((int)pfVar28 + 0x11));
      }
      else if (bVar14 == 5 || bVar14 == 7) {
        dVar40 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
        dVar53 = (double)(lVar16 * (longlong)(double)*(short *)((int)pfVar28 + 0x12));
      }
      else {
        dVar40 = (double)*pfVar26;
        dVar53 = (double)pfVar28[5];
      }
      pfVar26 = pfVar28 + 6;
      bVar14 = bVar13 & 7;
      if ((unaff_GQR0 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar15 & 0x3f));
      }
      if (bVar14 == 4 || bVar14 == 6) {
        dVar41 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
        dVar54 = (double)(lVar16 * (longlong)(double)*(char *)((int)pfVar28 + 0x19));
      }
      else if (bVar14 == 5 || bVar14 == 7) {
        dVar41 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
        dVar54 = (double)(lVar16 * (longlong)(double)*(short *)((int)pfVar28 + 0x1a));
      }
      else {
        dVar41 = (double)*pfVar26;
        dVar54 = (double)pfVar28[7];
      }
      pfVar26 = pfVar28 + 8;
      bVar14 = bVar13 & 7;
      if ((unaff_GQR0 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar15 & 0x3f));
      }
      if (bVar14 == 4 || bVar14 == 6) {
        dVar42 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
        dVar55 = (double)(lVar16 * (longlong)(double)*(char *)((int)pfVar28 + 0x21));
      }
      else if (bVar14 == 5 || bVar14 == 7) {
        dVar42 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
        dVar55 = (double)(lVar16 * (longlong)(double)*(short *)((int)pfVar28 + 0x22));
      }
      else {
        dVar42 = (double)*pfVar26;
        dVar55 = (double)pfVar28[9];
      }
      pfVar26 = pfVar28 + 10;
      bVar14 = bVar13 & 7;
      if ((unaff_GQR0 & 0x3f000000) == 0) {
        lVar16 = 0x3ff0000000000000;
      }
      else {
        lVar16 = ldexpf(-(bVar15 & 0x3f));
      }
      if (bVar14 == 4 || bVar14 == 6) {
        dVar43 = (double)(lVar16 * (longlong)(double)*(char *)pfVar26);
        dVar56 = (double)(lVar16 * (longlong)(double)*(char *)((int)pfVar28 + 0x29));
      }
      else if (bVar14 == 5 || bVar14 == 7) {
        dVar43 = (double)(lVar16 * (longlong)(double)*(short *)pfVar26);
        dVar56 = (double)(lVar16 * (longlong)(double)*(short *)((int)pfVar28 + 0x2a));
      }
      else {
        dVar43 = (double)*pfVar26;
        dVar56 = (double)pfVar28[0xb];
      }
      dVar57 = dVar48 * in_f12;
      dVar44 = dVar49 * in_f12;
      dVar58 = dVar39 * in_f12;
      dVar59 = dVar48 * in_f14;
      dVar45 = dVar49 * in_f14;
      dVar60 = dVar39 * in_f14;
      dVar48 = dVar48 * in_f16;
      dVar49 = dVar49 * in_f16;
      dVar39 = dVar39 * in_f16;
      dVar19 = dVar41 * dVar52;
      dVar21 = dVar54 * dVar52;
      dVar20 = dVar41 * in_ps14_1;
      dVar22 = dVar54 * in_ps14_1;
      dVar41 = dVar41 * in_ps16_1;
      dVar54 = dVar54 * in_ps16_1;
      in_f12 = dVar42 * in_f13 + dVar40 * dVar52 + dVar47 * in_f12;
      dVar52 = dVar55 * in_f13 + dVar53 * dVar52 + dVar57;
      dVar57 = dVar56 * in_f13;
      in_f14 = dVar42 * in_f15 + dVar40 * in_ps14_1 + dVar47 * in_f14;
      in_ps14_1 = dVar55 * in_f15 + dVar53 * in_ps14_1 + dVar59;
      dVar59 = dVar56 * in_f15;
      in_f16 = dVar42 * in_f17 + dVar40 * in_ps16_1 + dVar47 * in_f16;
      in_ps16_1 = dVar55 * in_f17 + dVar53 * in_ps16_1 + dVar48;
      dVar56 = dVar56 * in_f17;
      in_f13 = dVar50 * dVar46 + dVar43 * in_f13 + dVar19 + dVar44;
      dVar46 = dVar51 * dVar46 + dVar57 + dVar21 + dVar58;
      in_f15 = dVar50 * in_ps15_1 + dVar43 * in_f15 + dVar20 + dVar45;
      in_ps15_1 = dVar51 * in_ps15_1 + dVar59 + dVar22 + dVar60;
      in_f17 = dVar50 * in_ps17_1 + dVar43 * in_f17 + dVar41 + dVar49;
      in_ps17_1 = dVar51 * in_ps17_1 + dVar56 + dVar54 + dVar39;
      bVar14 = (byte)unaff_GQR0;
      bVar17 = bVar14 & 7;
      bVar18 = (byte)(unaff_GQR0 >> 8);
      if ((unaff_GQR0 & 0x3f00) == 0) {
        dVar47 = 1.0;
      }
      else {
        dVar47 = (double)ldexpf(bVar18 & 0x3f);
      }
      if (bVar17 == 4 || bVar17 == 6) {
        *(char *)pfVar28 = (char)(dVar47 * in_f12);
        *(char *)((int)pfVar28 + 1) = (char)(dVar47 * dVar52);
      }
      else if (bVar17 == 5 || bVar17 == 7) {
        *(short *)pfVar28 = (short)(dVar47 * in_f12);
        *(short *)((int)pfVar28 + 2) = (short)(dVar47 * dVar52);
      }
      else {
        *pfVar28 = (float)in_f12;
        pfVar28[1] = (float)dVar52;
      }
      pfVar26 = pfVar28 + 2;
      bVar17 = bVar14 & 7;
      if ((unaff_GQR0 & 0x3f00) == 0) {
        dVar47 = 1.0;
      }
      else {
        dVar47 = (double)ldexpf(bVar18 & 0x3f);
      }
      if (bVar17 == 4 || bVar17 == 6) {
        *(char *)pfVar26 = (char)(dVar47 * in_f13);
        *(char *)((int)pfVar28 + 9) = (char)(dVar47 * dVar46);
      }
      else if (bVar17 == 5 || bVar17 == 7) {
        *(short *)pfVar26 = (short)(dVar47 * in_f13);
        *(short *)((int)pfVar28 + 10) = (short)(dVar47 * dVar46);
      }
      else {
        *pfVar26 = (float)in_f13;
        pfVar28[3] = (float)dVar46;
      }
      pfVar26 = pfVar28 + 4;
      bVar17 = bVar14 & 7;
      if ((unaff_GQR0 & 0x3f00) == 0) {
        dVar47 = 1.0;
      }
      else {
        dVar47 = (double)ldexpf(bVar18 & 0x3f);
      }
      if (bVar17 == 4 || bVar17 == 6) {
        *(char *)pfVar26 = (char)(dVar47 * in_f14);
        *(char *)((int)pfVar28 + 0x11) = (char)(dVar47 * in_ps14_1);
      }
      else if (bVar17 == 5 || bVar17 == 7) {
        *(short *)pfVar26 = (short)(dVar47 * in_f14);
        *(short *)((int)pfVar28 + 0x12) = (short)(dVar47 * in_ps14_1);
      }
      else {
        *pfVar26 = (float)in_f14;
        pfVar28[5] = (float)in_ps14_1;
      }
      pfVar26 = pfVar28 + 6;
      bVar17 = bVar14 & 7;
      if ((unaff_GQR0 & 0x3f00) == 0) {
        dVar47 = 1.0;
      }
      else {
        dVar47 = (double)ldexpf(bVar18 & 0x3f);
      }
      if (bVar17 == 4 || bVar17 == 6) {
        *(char *)pfVar26 = (char)(dVar47 * in_f15);
        *(char *)((int)pfVar28 + 0x19) = (char)(dVar47 * in_ps15_1);
      }
      else if (bVar17 == 5 || bVar17 == 7) {
        *(short *)pfVar26 = (short)(dVar47 * in_f15);
        *(short *)((int)pfVar28 + 0x1a) = (short)(dVar47 * in_ps15_1);
      }
      else {
        *pfVar26 = (float)in_f15;
        pfVar28[7] = (float)in_ps15_1;
      }
      pfVar26 = pfVar28 + 8;
      bVar17 = bVar14 & 7;
      if ((unaff_GQR0 & 0x3f00) == 0) {
        dVar47 = 1.0;
      }
      else {
        dVar47 = (double)ldexpf(bVar18 & 0x3f);
      }
      if (bVar17 == 4 || bVar17 == 6) {
        *(char *)pfVar26 = (char)(dVar47 * in_f16);
        *(char *)((int)pfVar28 + 0x21) = (char)(dVar47 * in_ps16_1);
      }
      else if (bVar17 == 5 || bVar17 == 7) {
        *(short *)pfVar26 = (short)(dVar47 * in_f16);
        *(short *)((int)pfVar28 + 0x22) = (short)(dVar47 * in_ps16_1);
      }
      else {
        *pfVar26 = (float)in_f16;
        pfVar28[9] = (float)in_ps16_1;
      }
      pfVar26 = pfVar28 + 10;
      bVar14 = bVar14 & 7;
      if ((unaff_GQR0 & 0x3f00) == 0) {
        dVar47 = 1.0;
      }
      else {
        dVar47 = (double)ldexpf(bVar18 & 0x3f);
      }
      uVar33 = uVar25;
      if (bVar14 == 4 || bVar14 == 6) {
        *(char *)pfVar26 = (char)(dVar47 * in_f17);
        *(char *)((int)pfVar28 + 0x29) = (char)(dVar47 * in_ps17_1);
      }
      else if (bVar14 == 5 || bVar14 == 7) {
        *(short *)pfVar26 = (short)(dVar47 * in_f17);
        *(short *)((int)pfVar28 + 0x2a) = (short)(dVar47 * in_ps17_1);
      }
      else {
        *pfVar26 = (float)in_f17;
        pfVar28[0xb] = (float)in_ps17_1;
      }
    }
  }
  return;
}

