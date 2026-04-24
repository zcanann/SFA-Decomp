// Function: FUN_80006e34
// Entry: 80006e34
// Size: 1168 bytes

/* WARNING: Removing unreachable block (ram,0x80007e5c) */
/* WARNING: Removing unreachable block (ram,0x80007e50) */
/* WARNING: Removing unreachable block (ram,0x80007e58) */
/* WARNING: Removing unreachable block (ram,0x80007d7c) */
/* WARNING: Removing unreachable block (ram,0x80007274) */
/* WARNING: Removing unreachable block (ram,0x80007150) */
/* WARNING: Removing unreachable block (ram,0x80007160) */
/* WARNING: Removing unreachable block (ram,0x80007e4c) */
/* WARNING: Removing unreachable block (ram,0x80007e80) */
/* WARNING: Removing unreachable block (ram,0x80007e90) */
/* WARNING: Removing unreachable block (ram,0x80007e94) */
/* WARNING: Removing unreachable block (ram,0x80007e54) */
/* WARNING: Removing unreachable block (ram,0x80007e88) */
/* WARNING: Removing unreachable block (ram,0x80007170) */
/* WARNING: Removing unreachable block (ram,0x80007e60) */
/* WARNING: Removing unreachable block (ram,0x80007e84) */
/* WARNING: Removing unreachable block (ram,0x80007248) */
/* WARNING: Removing unreachable block (ram,0x80007e8c) */
/* WARNING: Removing unreachable block (ram,0x800072a0) */

double FUN_80006e34(double param_1,int param_2,undefined4 param_3,undefined4 param_4,
                   undefined4 param_5,int param_6,undefined4 param_7,uint param_8,uint param_9,
                   undefined4 param_10,undefined4 param_11)

{
  bool bVar1;
  short sVar2;
  short sVar3;
  int iVar4;
  undefined2 *in_r12;
  uint uVar5;
  short sVar6;
  int unaff_r16;
  float *pfVar7;
  uint uVar8;
  byte *pbVar9;
  int iVar10;
  byte *pbVar11;
  byte *pbVar12;
  uint uVar13;
  undefined2 *puVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int unaff_r31;
  bool bVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  double extraout_f1;
  double extraout_f1_00;
  float fVar22;
  float fVar23;
  double dVar24;
  float fVar25;
  float fVar26;
  double dVar27;
  undefined4 uVar28;
  undefined4 uVar29;
  undefined4 uVar30;
  float fVar31;
  double in_f6;
  float fVar32;
  float fVar33;
  double in_f7;
  float fVar34;
  float fVar35;
  double in_f8;
  float fVar36;
  undefined4 in_ps9_0;
  float fVar37;
  undefined4 in_ps9_1;
  float fVar38;
  float fVar39;
  double in_f10;
  float fVar40;
  float fVar41;
  double in_f11;
  float fVar42;
  float fVar43;
  double in_f12;
  float fVar44;
  double in_f13;
  float fVar45;
  float fVar46;
  double in_f14;
  float fVar47;
  float fVar48;
  double in_f15;
  float fVar49;
  double in_f16;
  float fVar50;
  double in_f17;
  float fVar51;
  float fVar52;
  double in_f18;
  float fVar53;
  double in_f19;
  double dVar54;
  double dVar55;
  double dVar56;
  double dVar57;
  double dVar58;
  double in_f28;
  double dVar59;
  double in_f30;
  double dVar60;
  undefined8 uVar61;
  
  uVar61 = CONCAT44(param_2,param_3);
  uVar21 = 0x70007;
  uVar20 = 0x50005;
  uVar19 = 0;
  if ((param_9 & 0x20) != 0) {
    *in_r12 = DAT_803dc7a4;
    in_r12[1] = DAT_803dc7a6;
    in_r12[2] = DAT_803dc7a8;
  }
  iVar10 = unaff_r31;
  if (((param_9 & 0xc) != 0) && (iVar10 = param_2 + 0x1c, (param_9 & 8) != 0)) {
    iVar10 = param_2 + 0x22;
  }
  dVar60 = (double)FLOAT_803de510;
  dVar59 = (double)FLOAT_803de514;
  dVar58 = (double)(float)(dVar60 - in_f28);
  pbVar9 = DAT_803dc7a0 + param_6 * 0x1c;
  pbVar11 = DAT_803dc7a0;
  do {
    puVar14 = in_r12 + (uint)pbVar11[3] * 0x20;
    iVar15 = unaff_r31 + (uint)pbVar11[2] * 0x40;
    iVar16 = iVar10 + (uint)pbVar11[2] * 0x40;
    iVar4 = 2;
    if ((param_9 & 0xf) != 0) {
      iVar17 = (pbVar11[1] & 0x7f) * 0x40;
      iVar16 = iVar10 + iVar17;
      if ((param_9 & 3) != 0) {
        if ((param_9 & 1) == 0) {
          puVar14 = in_r12 + (pbVar11[1] & 0x7f) * 0x20;
        }
        else {
          iVar15 = unaff_r31 + iVar17;
        }
      }
    }
    do {
      uVar8 = (uint)(ushort)puVar14[6];
      if (uVar8 == 0) {
        uVar8 = 0x400;
      }
      uVar5 = (uint)*(ushort *)(iVar15 + 0xc);
      if (uVar5 == 0) {
        uVar5 = 0x400;
      }
      uVar8 = (uVar8 - uVar5) * unaff_r16;
      bVar18 = (int)uVar8 < 0 && (uVar8 & 0x3fff) != 0;
      *(short *)(iVar16 + 0xc) = (short)((int)uVar8 >> 0xe) + (short)uVar5;
      sVar6 = *(short *)(iVar15 + 0x18);
      iVar15 = iVar15 + 2;
      if ((param_9 & 0x10) == 0) {
        uVar8 = ((int)(short)puVar14[0xc] - (int)sVar6) * unaff_r16;
        bVar18 = (int)uVar8 < 0 && (uVar8 & 0x3fff) != 0;
        sVar6 = sVar6 + (short)((int)uVar8 >> 0xe);
      }
      *(short *)(iVar16 + 0x18) = sVar6;
      iVar16 = iVar16 + 2;
      bVar1 = iVar4 != 0;
      iVar4 = iVar4 + (bVar18 - 1);
      puVar14 = puVar14 + 1;
    } while (bVar1);
    pbVar11 = pbVar11 + 0x1c;
    uVar8 = param_8;
    iVar4 = param_6;
    pbVar12 = DAT_803dc7a0;
  } while (pbVar11 != pbVar9);
  do {
    while( true ) {
      while( true ) {
        iVar15 = (uint)pbVar12[2] << 6;
        if ((param_9 & 1) == 0) {
          uVar61 = FUN_800072c4();
          in_f14 = (double)(float)(in_f7 * in_f18);
          fVar52 = (float)(in_f10 + in_f11);
          in_f15 = (double)(float)(in_f8 * in_f19);
          fVar45 = (float)(in_f12 - in_f13);
          in_f16 = (double)(float)(in_f6 * in_f19);
          fVar53 = (float)(in_f14 + in_f15);
          in_f17 = (double)(float)((double)CONCAT44(in_ps9_0,in_ps9_1) * in_f18);
          fVar48 = (float)(in_f16 - in_f17);
          param_1 = extraout_f1;
        }
        else {
          iVar15 = (pbVar12[1] & 0x7f) * 0x40;
          pfVar7 = (float *)(iVar15 + (int)((ulonglong)uVar61 >> 0x20));
          fVar52 = *pfVar7;
          fVar45 = pfVar7[1];
          fVar53 = pfVar7[2];
          fVar48 = pfVar7[3];
        }
        dVar57 = (double)fVar48;
        dVar56 = (double)fVar53;
        dVar55 = (double)fVar45;
        dVar54 = (double)fVar52;
        iVar15 = iVar10 + iVar15;
        if ((param_9 & 2) == 0) {
          uVar61 = FUN_800072c4();
          in_f14 = (double)(float)(in_f7 * in_f18);
          fVar52 = (float)(in_f10 + in_f11);
          in_f15 = (double)(float)(in_f8 * in_f19);
          fVar45 = (float)(in_f12 - in_f13);
          in_f16 = (double)(float)(in_f6 * in_f19);
          fVar53 = (float)(in_f14 + in_f15);
          in_f17 = (double)(float)((double)CONCAT44(in_ps9_0,in_ps9_1) * in_f18);
          fVar48 = (float)(in_f16 - in_f17);
          param_1 = extraout_f1_00;
        }
        else {
          iVar16 = (pbVar12[1] & 0x7f) * 0x40 + (int)((ulonglong)uVar61 >> 0x20);
          fVar52 = *(float *)(iVar16 + 0x10);
          fVar45 = *(float *)(iVar16 + 0x14);
          fVar53 = *(float *)(iVar16 + 0x18);
          fVar48 = *(float *)(iVar16 + 0x1c);
        }
        iVar16 = (int)((ulonglong)uVar61 >> 0x20);
        iVar17 = (int)uVar61;
        in_f7 = (double)fVar48;
        in_f6 = (double)fVar53;
        dVar27 = (double)fVar45;
        dVar24 = (double)fVar52;
        in_f11 = (double)(float)(dVar55 * dVar27);
        in_f12 = (double)(float)(dVar56 * in_f6);
        in_f13 = (double)(float)(dVar57 * in_f7);
        in_f10 = (double)(float)((double)(float)((double)(float)((double)(float)(dVar54 * dVar24) +
                                                                in_f11) + in_f12) + in_f13);
        if (in_f10 < in_f30) {
          dVar24 = (double)(float)(in_f30 - dVar24);
          dVar27 = (double)(float)(in_f30 - dVar27);
          in_f6 = (double)(float)(in_f30 - in_f6);
          in_f7 = (double)(float)(in_f30 - in_f7);
        }
        if (-1 < (int)((int)(char)pbVar12[1] & param_8)) break;
        iVar4 = iVar4 + -1;
        pbVar12 = pbVar12 + 0x1c;
        if (iVar4 == 0) goto LAB_80007d74;
      }
      fVar45 = (float)(dVar54 * dVar58) + (float)(dVar24 * in_f28);
      in_f10 = (double)fVar45;
      in_f6 = (double)(float)(in_f6 * in_f28);
      fVar48 = (float)(dVar55 * dVar58) + (float)(dVar27 * in_f28);
      in_f11 = (double)fVar48;
      in_f7 = (double)(float)(in_f7 * in_f28);
      fVar52 = (float)((double)(float)(dVar56 * dVar58) + in_f6);
      in_f12 = (double)fVar52;
      fVar53 = (float)((double)(float)(dVar57 * dVar58) + in_f7);
      in_f13 = (double)fVar53;
      if ((param_9 & 0xc) == 0) break;
      if ((param_9 & 8) != 0) {
        iVar16 = iVar16 + 0x10;
      }
      pfVar7 = (float *)((pbVar12[1] & 0x7f) * 0x40 + iVar16);
      *pfVar7 = fVar45;
      pfVar7[1] = fVar48;
      pfVar7[2] = fVar52;
      pfVar7[3] = fVar53;
      iVar4 = iVar4 + -1;
      pbVar12 = pbVar12 + 0x1c;
      if (iVar4 == 0) {
        return param_1;
      }
    }
    dVar55 = (double)(float)(in_f12 * dVar59);
    pfVar7 = (float *)(DAT_803db1e0 + ((int)(char)pbVar12[1] & param_8 & 0x7f) * 0x40);
    dVar54 = (double)FLOAT_803de518;
    uVar28 = __psq_l0(iVar15 + 0x18,uVar21);
    uVar29 = __psq_l0(iVar15 + 0x1a,uVar21);
    fVar52 = *(float *)(pbVar12 + 8);
    uVar30 = __psq_l0(iVar15 + 0x1c,uVar21);
    fVar53 = *(float *)(pbVar12 + 0xc);
    sVar6 = *(short *)(iVar15 + 0xc);
    sVar2 = *(short *)(iVar15 + 0xe);
    sVar3 = *(short *)(iVar15 + 0x10);
    pfVar7[3] = (float)((double)CONCAT44(uVar28,0x3f800000) * dVar54) + *(float *)(pbVar12 + 4);
    dVar56 = (double)(float)(in_f13 * dVar59);
    dVar57 = (double)(float)(in_f10 * (double)(float)(in_f11 * dVar59));
    pfVar7[0xb] = (float)((double)CONCAT44(uVar30,0x3f800000) * dVar54) + fVar53;
    pfVar7[7] = (float)((double)CONCAT44(uVar29,0x3f800000) * dVar54) + fVar52;
    dVar54 = in_f10 * dVar56;
    in_f6 = (double)(float)(in_f11 * (double)(float)(in_f11 * dVar59));
    in_f7 = (double)(float)(in_f11 * dVar55);
    in_f8 = (double)(float)(in_f11 * dVar56);
    fVar52 = (float)(in_f7 + (double)(float)dVar54);
    in_f17 = (double)(float)(in_f13 * dVar56);
    fVar48 = (float)(in_f8 - (double)(float)(in_f10 * dVar55));
    in_f15 = (double)(float)(in_f12 * dVar55);
    fVar53 = (float)(in_f8 + (double)(float)(in_f10 * dVar55));
    in_f16 = (double)(float)(in_f12 * dVar56);
    fVar49 = (float)(dVar60 - (double)(float)(in_f15 + in_f17));
    in_f19 = (double)fVar49;
    fVar50 = (float)(in_f16 - dVar57);
    fVar51 = (float)(dVar60 - (double)(float)(in_f6 + in_f15));
    in_f10 = (double)fVar51;
    fVar45 = (float)(in_f16 + dVar57);
    fVar22 = (float)(in_f7 - (double)(float)dVar54);
    fVar23 = (float)(dVar60 - (double)(float)(in_f6 + in_f17));
    param_1 = (double)FLOAT_803de51c;
    if (sVar6 == 0) {
      *pfVar7 = fVar49;
      pfVar7[1] = fVar52;
      pfVar7[2] = fVar48;
      if (sVar2 != 0) goto LAB_80007270;
LAB_80007210:
      pfVar7[1] = fVar22;
      pfVar7[5] = fVar23;
      pfVar7[9] = fVar45;
      if (sVar3 != 0) goto LAB_8000729c;
LAB_80007224:
      pfVar7[2] = fVar53;
      pfVar7[6] = fVar50;
      pfVar7[10] = fVar51;
    }
    else {
      uVar28 = __psq_l0(&param_11,uVar20);
      dVar55 = (double)(float)((double)CONCAT44(uVar28,0x3f800000) * param_1);
      dVar54 = in_f19 * dVar55;
      in_f19 = (double)(float)dVar54;
      *pfVar7 = (float)dVar54;
      pfVar7[4] = (float)((double)fVar52 * dVar55);
      pfVar7[8] = (float)((double)fVar48 * dVar55);
      param_11._0_2_ = sVar6;
      if (sVar2 == 0) goto LAB_80007210;
LAB_80007270:
      uVar28 = __psq_l0(&param_11,uVar20);
      fVar52 = (float)((double)CONCAT44(uVar28,0x3f800000) * param_1);
      pfVar7[1] = fVar22 * fVar52;
      pfVar7[5] = fVar23 * fVar52;
      pfVar7[9] = fVar45 * fVar52;
      param_11._0_2_ = sVar2;
      if (sVar3 == 0) goto LAB_80007224;
LAB_8000729c:
      uVar28 = __psq_l0(&param_11,uVar20);
      dVar54 = (double)(float)((double)CONCAT44(uVar28,0x3f800000) * param_1);
      pfVar7[2] = (float)((double)fVar53 * dVar54);
      pfVar7[6] = (float)((double)fVar50 * dVar54);
      dVar54 = in_f10 * dVar54;
      in_f10 = (double)(float)dVar54;
      pfVar7[10] = (float)dVar54;
      param_11._0_2_ = sVar3;
    }
    iVar4 = iVar4 + -1;
    pbVar12 = pbVar12 + 0x1c;
  } while (iVar4 != 0);
LAB_80007d74:
  fVar52 = (float)__psq_l0(0x803de500,uVar19);
  fVar53 = (float)__psq_l1(0x803de500,uVar19);
  if ((param_9 & 0xc) == 0) {
    uVar5 = (int)(char)DAT_803dc7a0[1] & 0x7f;
    iVar10 = uVar5 * 0x40 + DAT_803db1e0;
    pbVar11 = DAT_803dc7a0;
    if (-1 < (int)((int)(char)DAT_803dc7a0[1] & uVar8)) goto LAB_80007e4c;
    uVar13 = 0xfffffffb;
    while (param_6 = param_6 + -1, dVar58 = in_f13, param_6 != 0) {
      while( true ) {
        in_f13 = dVar58;
        pbVar11 = pbVar11 + 0x1c;
        uVar5 = (int)(char)pbVar11[1] & uVar8;
        if ((int)uVar5 < 0) break;
        iVar10 = uVar5 * 0x40 + DAT_803db1e0;
        if (*pbVar11 != uVar13) {
          iVar17 = (uint)*pbVar11 * 0x40 + DAT_803db1e0;
LAB_80007e4c:
          uVar20 = __psq_l0(iVar17,uVar19);
          uVar21 = __psq_l1(iVar17,uVar19);
          in_f12 = (double)CONCAT44(uVar20,uVar21);
          uVar20 = __psq_l0(iVar17 + 8,uVar19);
          uVar21 = __psq_l1(iVar17 + 8,uVar19);
          in_f13 = (double)CONCAT44(uVar20,uVar21);
          uVar20 = __psq_l0(iVar17 + 0x10,uVar19);
          uVar21 = __psq_l1(iVar17 + 0x10,uVar19);
          in_f14 = (double)CONCAT44(uVar20,uVar21);
          uVar20 = __psq_l0(iVar17 + 0x18,uVar19);
          uVar21 = __psq_l1(iVar17 + 0x18,uVar19);
          in_f15 = (double)CONCAT44(uVar20,uVar21);
          uVar20 = __psq_l0(iVar17 + 0x20,uVar19);
          uVar21 = __psq_l1(iVar17 + 0x20,uVar19);
          in_f16 = (double)CONCAT44(uVar20,uVar21);
          uVar20 = __psq_l0(iVar17 + 0x28,uVar19);
          uVar21 = __psq_l1(iVar17 + 0x28,uVar19);
          in_f17 = (double)CONCAT44(uVar20,uVar21);
        }
        fVar31 = (float)__psq_l0(iVar10,uVar19);
        fVar32 = (float)__psq_l1(iVar10,uVar19);
        fVar33 = (float)__psq_l0(iVar10 + 8,uVar19);
        fVar34 = (float)__psq_l1(iVar10 + 8,uVar19);
        fVar35 = (float)__psq_l0(iVar10 + 0x10,uVar19);
        fVar36 = (float)__psq_l1(iVar10 + 0x10,uVar19);
        fVar37 = (float)__psq_l0(iVar10 + 0x18,uVar19);
        fVar38 = (float)__psq_l1(iVar10 + 0x18,uVar19);
        fVar39 = (float)__psq_l0(iVar10 + 0x20,uVar19);
        fVar40 = (float)__psq_l1(iVar10 + 0x20,uVar19);
        fVar41 = (float)__psq_l0(iVar10 + 0x28,uVar19);
        fVar42 = (float)__psq_l1(iVar10 + 0x28,uVar19);
        fVar45 = (float)((ulonglong)in_f12 >> 0x20);
        fVar50 = (float)((ulonglong)in_f14 >> 0x20);
        fVar23 = (float)((ulonglong)in_f16 >> 0x20);
        fVar48 = SUB84(in_f12,0);
        fVar51 = SUB84(in_f14,0);
        fVar25 = SUB84(in_f16,0);
        fVar49 = (float)((ulonglong)in_f13 >> 0x20);
        fVar43 = fVar39 * fVar49 + fVar35 * fVar48 + fVar31 * fVar45;
        fVar44 = fVar40 * fVar49 + fVar36 * fVar48 + fVar32 * fVar45;
        in_f12 = (double)CONCAT44(fVar43,fVar44);
        fVar22 = (float)((ulonglong)in_f15 >> 0x20);
        fVar46 = fVar39 * fVar22 + fVar35 * fVar51 + fVar31 * fVar50;
        fVar47 = fVar40 * fVar22 + fVar36 * fVar51 + fVar32 * fVar50;
        in_f14 = (double)CONCAT44(fVar46,fVar47);
        fVar26 = (float)((ulonglong)in_f17 >> 0x20);
        fVar35 = fVar39 * fVar26 + fVar35 * fVar25 + fVar31 * fVar23;
        fVar32 = fVar40 * fVar26 + fVar36 * fVar25 + fVar32 * fVar23;
        in_f16 = (double)CONCAT44(fVar35,fVar32);
        fVar31 = fVar52 * SUB84(in_f13,0) + fVar41 * fVar49 + fVar37 * fVar48 + fVar33 * fVar45;
        fVar45 = fVar53 * SUB84(in_f13,0) + fVar42 * fVar49 + fVar38 * fVar48 + fVar34 * fVar45;
        fVar48 = fVar52 * SUB84(in_f15,0) + fVar41 * fVar22 + fVar37 * fVar51 + fVar33 * fVar50;
        fVar49 = fVar53 * SUB84(in_f15,0) + fVar42 * fVar22 + fVar38 * fVar51 + fVar34 * fVar50;
        in_f15 = (double)CONCAT44(fVar48,fVar49);
        fVar50 = fVar52 * SUB84(in_f17,0) + fVar41 * fVar26 + fVar37 * fVar25 + fVar33 * fVar23;
        fVar51 = fVar53 * SUB84(in_f17,0) + fVar42 * fVar26 + fVar38 * fVar25 + fVar34 * fVar23;
        in_f17 = (double)CONCAT44(fVar50,fVar51);
        __psq_st0(iVar10,fVar43,uVar19);
        __psq_st1(iVar10,fVar44,uVar19);
        __psq_st0(iVar10 + 8,fVar31,uVar19);
        __psq_st1(iVar10 + 8,fVar45,uVar19);
        __psq_st0(iVar10 + 0x10,fVar46,uVar19);
        __psq_st1(iVar10 + 0x10,fVar47,uVar19);
        __psq_st0(iVar10 + 0x18,fVar48,uVar19);
        __psq_st1(iVar10 + 0x18,fVar49,uVar19);
        __psq_st0(iVar10 + 0x20,fVar35,uVar19);
        __psq_st1(iVar10 + 0x20,fVar32,uVar19);
        __psq_st0(iVar10 + 0x28,fVar50,uVar19);
        __psq_st1(iVar10 + 0x28,fVar51,uVar19);
        param_6 = param_6 + -1;
        uVar13 = uVar5;
        param_1 = in_f13;
        dVar58 = (double)CONCAT44(fVar31,fVar45);
        if (param_6 == 0) {
          return in_f13;
        }
      }
      uVar13 = 0xffffffff;
    }
  }
  return param_1;
}

