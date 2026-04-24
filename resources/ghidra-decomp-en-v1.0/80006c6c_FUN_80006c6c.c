// Function: FUN_80006c6c
// Entry: 80006c6c
// Size: 1984 bytes

/* WARNING: Removing unreachable block (ram,0x80006dcc) */
/* WARNING: Removing unreachable block (ram,0x80006db8) */
/* WARNING: Removing unreachable block (ram,0x80006d74) */
/* WARNING: Removing unreachable block (ram,0x80007e54) */
/* WARNING: Removing unreachable block (ram,0x80007e94) */
/* WARNING: Removing unreachable block (ram,0x80007e60) */
/* WARNING: Removing unreachable block (ram,0x80007e4c) */
/* WARNING: Removing unreachable block (ram,0x80007be0) */
/* WARNING: Removing unreachable block (ram,0x80007bf4) */
/* WARNING: Removing unreachable block (ram,0x80007ad0) */
/* WARNING: Removing unreachable block (ram,0x80007a54) */
/* WARNING: Removing unreachable block (ram,0x80007b4c) */
/* WARNING: Removing unreachable block (ram,0x80007cfc) */
/* WARNING: Removing unreachable block (ram,0x80007d7c) */
/* WARNING: Removing unreachable block (ram,0x80007e50) */
/* WARNING: Removing unreachable block (ram,0x80007e80) */
/* WARNING: Removing unreachable block (ram,0x80007e58) */
/* WARNING: Removing unreachable block (ram,0x80006dbc) */
/* WARNING: Removing unreachable block (ram,0x80006e08) */
/* WARNING: Removing unreachable block (ram,0x80007e8c) */
/* WARNING: Removing unreachable block (ram,0x80007e84) */
/* WARNING: Removing unreachable block (ram,0x80007c08) */
/* WARNING: Removing unreachable block (ram,0x80007e5c) */
/* WARNING: Removing unreachable block (ram,0x80007e88) */
/* WARNING: Removing unreachable block (ram,0x80007cbc) */
/* WARNING: Removing unreachable block (ram,0x80007e90) */
/* WARNING: Removing unreachable block (ram,0x80007d40) */

double FUN_80006c6c(int *param_1,undefined4 param_2,int param_3,byte *param_4,int param_5,
                   undefined4 param_6,uint param_7,uint param_8)

{
  short sVar1;
  float *pfVar2;
  int extraout_r4;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  byte *pbVar6;
  int iVar7;
  int iVar8;
  byte *pbVar9;
  undefined4 uVar10;
  double dVar11;
  undefined4 uVar12;
  double dVar13;
  double dVar14;
  float fVar15;
  undefined4 uVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  double dVar21;
  float fVar22;
  float fVar23;
  double dVar24;
  double dVar25;
  double dVar26;
  float fVar27;
  float fVar28;
  double dVar29;
  float fVar30;
  undefined4 uVar31;
  float fVar32;
  double dVar33;
  float fVar34;
  float fVar35;
  double dVar36;
  float fVar37;
  float fVar38;
  float fVar39;
  float fVar40;
  double in_f12;
  float fVar41;
  double in_f13;
  float fVar42;
  float fVar43;
  double in_f14;
  float fVar44;
  float fVar45;
  double in_f15;
  float fVar46;
  double in_f16;
  double dVar47;
  float fVar48;
  double in_f17;
  float fVar49;
  float fVar50;
  float fVar51;
  double dVar52;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double dVar53;
  double dVar54;
  double in_f31;
  undefined local_f0 [24];
  
  uVar12 = 0x70007;
  uVar10 = 0x50005;
  uVar16 = 0;
  DAT_803db1e0 = *param_1;
  dVar54 = (double)FLOAT_803de508;
  DAT_803db1e4 = param_1;
  DAT_803dc7a0 = param_4;
  if ((param_8 & 0x40) == 0) {
    if (((param_8 & 1) == 0) &&
       (dVar13 = (double)FUN_800074ec(), iVar7 = DAT_803db1e0, *(short *)(param_3 + 0x58) < 1)) {
      pbVar9 = DAT_803dc7a0 + param_5 * 0x1c;
      dVar52 = (double)FLOAT_803de51c;
      dVar53 = (double)FLOAT_803de518;
      pbVar6 = DAT_803dc7a0;
      do {
        while ((int)((int)(char)pbVar6[1] & param_7) < 0) {
joined_r0x80007d70:
          pbVar6 = pbVar6 + 0x1c;
          if (pbVar6 == pbVar9) goto LAB_80007d74;
        }
        pfVar2 = (float *)(((int)(char)pbVar6[1] & param_7) * 0x40 + iVar7);
        iVar8 = (uint)pbVar6[2] * 0x40;
        DAT_80335840 = (float)in_f23;
        DAT_80335844 = (float)in_f24;
        DAT_80335848 = (float)in_f25;
        DAT_8033584c = (float)in_f26;
        DAT_80335850 = (float)in_f27;
        DAT_80335854 = (float)in_f28;
        DAT_80335858 = (float)dVar53;
        DAT_8033585c = (float)dVar54;
        DAT_80335860 = (float)in_f31;
        uVar31 = __psq_l0(0x80335864,uVar12);
        dVar54 = (double)CONCAT44(uVar31,0x3f800000);
        fVar50 = (float)(dVar54 * dVar54);
        dVar13 = (double)(float)(dVar54 * (double)(fVar50 * (fVar50 * (fVar50 * FLOAT_803de534 +
                                                                      FLOAT_803de538) +
                                                            FLOAT_803de53c) + FLOAT_803de540));
        dVar54 = (double)(fVar50 * (fVar50 * (fVar50 * (fVar50 * FLOAT_803de520 + FLOAT_803de524) +
                                             FLOAT_803de528) + FLOAT_803de52c) + FLOAT_803de530);
        uVar3 = *(short *)(&DAT_802c3580 + iVar8) + 0x2000U & 0xc000;
        dVar11 = dVar54;
        if (uVar3 != 0) {
          if (uVar3 == 0x4000) {
            dVar11 = -dVar13;
            dVar13 = dVar54;
          }
          else if (uVar3 == 0x8000) {
            dVar11 = -dVar54;
            dVar13 = -dVar13;
          }
          else {
            dVar11 = dVar13;
            dVar13 = -dVar54;
          }
        }
        uVar31 = __psq_l0(0x80335864,uVar12);
        dVar54 = (double)CONCAT44(uVar31,0x3f800000);
        fVar50 = (float)(dVar54 * dVar54);
        dVar24 = (double)(float)(dVar54 * (double)(fVar50 * (fVar50 * (fVar50 * FLOAT_803de534 +
                                                                      FLOAT_803de538) +
                                                            FLOAT_803de53c) + FLOAT_803de540));
        dVar54 = (double)(fVar50 * (fVar50 * (fVar50 * (fVar50 * FLOAT_803de520 + FLOAT_803de524) +
                                             FLOAT_803de528) + FLOAT_803de52c) + FLOAT_803de530);
        uVar3 = *(short *)(&DAT_802c3582 + iVar8) + 0x2000U & 0xc000;
        dVar14 = dVar54;
        if (uVar3 != 0) {
          if (uVar3 == 0x4000) {
            dVar14 = -dVar24;
            dVar24 = dVar54;
          }
          else if (uVar3 == 0x8000) {
            dVar14 = -dVar54;
            dVar24 = -dVar24;
          }
          else {
            dVar14 = dVar24;
            dVar24 = -dVar54;
          }
        }
        DAT_80335864 = *(short *)(&DAT_802c3584 + iVar8) << 2;
        uVar31 = __psq_l0(0x80335864,uVar12);
        dVar54 = (double)CONCAT44(uVar31,0x3f800000);
        fVar50 = (float)(dVar54 * dVar54);
        dVar25 = (double)(float)(dVar54 * (double)(fVar50 * (fVar50 * (fVar50 * FLOAT_803de534 +
                                                                      FLOAT_803de538) +
                                                            FLOAT_803de53c) + FLOAT_803de540));
        dVar54 = (double)(fVar50 * (fVar50 * (fVar50 * (fVar50 * FLOAT_803de520 + FLOAT_803de524) +
                                             FLOAT_803de528) + FLOAT_803de52c) + FLOAT_803de530);
        uVar3 = *(short *)(&DAT_802c3584 + iVar8) + 0x2000U & 0xc000;
        dVar47 = dVar54;
        if (uVar3 != 0) {
          if (uVar3 == 0x4000) {
            dVar47 = -dVar25;
            dVar25 = dVar54;
          }
          else if (uVar3 == 0x8000) {
            dVar47 = -dVar54;
            dVar25 = -dVar25;
          }
          else {
            dVar47 = dVar25;
            dVar25 = -dVar54;
          }
        }
        in_f23 = (double)DAT_80335840;
        in_f24 = (double)DAT_80335844;
        in_f25 = (double)DAT_80335848;
        in_f26 = (double)DAT_8033584c;
        in_f27 = (double)DAT_80335850;
        in_f28 = (double)DAT_80335854;
        dVar53 = (double)DAT_80335858;
        dVar54 = (double)DAT_8033585c;
        in_f31 = (double)DAT_80335860;
        uVar31 = __psq_l0(iVar8 + -0x7fd3ca68,uVar12);
        pfVar2[3] = *(float *)(pbVar6 + 4) + (float)((double)CONCAT44(uVar31,0x3f800000) * dVar53);
        uVar31 = __psq_l0(iVar8 + -0x7fd3ca66,uVar12);
        pfVar2[7] = *(float *)(pbVar6 + 8) + (float)((double)CONCAT44(uVar31,0x3f800000) * dVar53);
        uVar31 = __psq_l0(iVar8 + -0x7fd3ca64,uVar12);
        dVar26 = (double)(float)(dVar11 * dVar25);
        pfVar2[0xb] = *(float *)(pbVar6 + 0xc) +
                      (float)((double)CONCAT44(uVar31,0x3f800000) * dVar53);
        dVar21 = (double)(float)(dVar13 * dVar25);
        dVar29 = (double)(float)(dVar13 * dVar47);
        dVar33 = (double)(float)(dVar11 * dVar47);
        in_f12 = (double)(float)(dVar14 * dVar47);
        in_f13 = (double)(float)(dVar14 * dVar25);
        if (*(short *)(&DAT_802c358c + iVar8) != 0) {
          uVar31 = __psq_l0(local_f0,uVar10);
          dVar25 = (double)(float)((double)CONCAT44(uVar31,0x3f800000) * dVar52);
          dVar47 = in_f12 * dVar25;
          in_f12 = (double)(float)dVar47;
          *pfVar2 = (float)dVar47;
          dVar47 = in_f13 * dVar25;
          in_f13 = (double)(float)dVar47;
          sVar1 = *(short *)(&DAT_802c358e + iVar8);
          fVar50 = (float)((double)(float)(dVar54 - dVar24) * dVar25);
          in_f14 = (double)fVar50;
          pfVar2[4] = (float)dVar47;
          if (sVar1 == 0) goto LAB_80007c4c;
          pfVar2[8] = fVar50;
          in_f15 = (double)(float)((double)(float)(dVar29 * dVar24) - dVar26);
          dVar47 = (double)(float)(dVar21 * dVar24);
LAB_80007cf8:
          uVar31 = __psq_l0(local_f0,uVar10);
          dVar36 = (double)(float)((double)CONCAT44(uVar31,0x3f800000) * dVar52);
          dVar25 = in_f15 * dVar36;
          in_f15 = (double)(float)dVar25;
          pfVar2[1] = (float)dVar25;
          fVar50 = (float)((double)(float)(dVar47 + dVar33) * dVar36);
          in_f16 = (double)fVar50;
          sVar1 = *(short *)(&DAT_802c3590 + iVar8);
          fVar51 = (float)((double)(float)(dVar13 * dVar14) * dVar36);
          in_f17 = (double)fVar51;
          pfVar2[5] = fVar50;
          if (sVar1 == 0) goto LAB_80007c78;
          pfVar2[9] = fVar51;
          fVar50 = (float)((double)(float)(dVar33 * dVar24) + dVar21);
          dVar24 = (double)(float)(dVar26 * dVar24);
LAB_80007d3c:
          uVar31 = __psq_l0(local_f0,uVar10);
          fVar51 = (float)((double)CONCAT44(uVar31,0x3f800000) * dVar52);
          pfVar2[2] = fVar50 * fVar51;
          pfVar2[6] = (float)(dVar24 - dVar29) * fVar51;
          pfVar2[10] = (float)(dVar11 * dVar14) * fVar51;
          goto joined_r0x80007d70;
        }
        *pfVar2 = (float)(dVar14 * dVar47);
        in_f14 = (double)(float)(dVar54 - dVar24);
        pfVar2[4] = (float)(dVar14 * dVar25);
LAB_80007c4c:
        pfVar2[8] = (float)in_f14;
        fVar50 = (float)((double)(float)(dVar29 * dVar24) - dVar26);
        in_f15 = (double)fVar50;
        dVar47 = (double)(float)(dVar21 * dVar24);
        if (*(short *)(&DAT_802c358e + iVar8) != 0) goto LAB_80007cf8;
        pfVar2[1] = fVar50;
        in_f16 = (double)(float)(dVar47 + dVar33);
        in_f17 = (double)(float)(dVar13 * dVar14);
        pfVar2[5] = (float)(dVar47 + dVar33);
LAB_80007c78:
        pfVar2[9] = (float)in_f17;
        fVar50 = (float)((double)(float)(dVar33 * dVar24) + dVar21);
        dVar24 = (double)(float)(dVar26 * dVar24);
        if (*(short *)(&DAT_802c3590 + iVar8) != 0) goto LAB_80007d3c;
        pfVar2[2] = fVar50;
        pfVar2[6] = (float)(dVar24 - dVar29);
        pbVar6 = pbVar6 + 0x1c;
        pfVar2[10] = (float)(dVar11 * dVar14);
      } while (pbVar6 != pbVar9);
LAB_80007d74:
      fVar50 = (float)__psq_l0(0x803de500,uVar16);
      fVar51 = (float)__psq_l1(0x803de500,uVar16);
      if ((param_8 & 0xc) == 0) {
        uVar4 = (int)(char)DAT_803dc7a0[1] & 0x7f;
        iVar8 = uVar4 * 0x40 + DAT_803db1e0;
        pbVar6 = DAT_803dc7a0;
        iVar7 = extraout_r4;
        if (-1 < (int)((int)(char)DAT_803dc7a0[1] & param_7)) goto LAB_80007e4c;
        uVar5 = 0xfffffffb;
        while (param_5 = param_5 + -1, dVar54 = in_f13, param_5 != 0) {
          while( true ) {
            in_f13 = dVar54;
            pbVar6 = pbVar6 + 0x1c;
            uVar4 = (int)(char)pbVar6[1] & param_7;
            if ((int)uVar4 < 0) break;
            iVar8 = uVar4 * 0x40 + DAT_803db1e0;
            if (*pbVar6 != uVar5) {
              iVar7 = (uint)*pbVar6 * 0x40 + DAT_803db1e0;
LAB_80007e4c:
              uVar10 = __psq_l0(iVar7,uVar16);
              uVar12 = __psq_l1(iVar7,uVar16);
              in_f12 = (double)CONCAT44(uVar10,uVar12);
              uVar10 = __psq_l0(iVar7 + 8,uVar16);
              uVar12 = __psq_l1(iVar7 + 8,uVar16);
              in_f13 = (double)CONCAT44(uVar10,uVar12);
              uVar10 = __psq_l0(iVar7 + 0x10,uVar16);
              uVar12 = __psq_l1(iVar7 + 0x10,uVar16);
              in_f14 = (double)CONCAT44(uVar10,uVar12);
              uVar10 = __psq_l0(iVar7 + 0x18,uVar16);
              uVar12 = __psq_l1(iVar7 + 0x18,uVar16);
              in_f15 = (double)CONCAT44(uVar10,uVar12);
              uVar10 = __psq_l0(iVar7 + 0x20,uVar16);
              uVar12 = __psq_l1(iVar7 + 0x20,uVar16);
              in_f16 = (double)CONCAT44(uVar10,uVar12);
              uVar10 = __psq_l0(iVar7 + 0x28,uVar16);
              uVar12 = __psq_l1(iVar7 + 0x28,uVar16);
              in_f17 = (double)CONCAT44(uVar10,uVar12);
            }
            fVar20 = (float)__psq_l0(iVar8,uVar16);
            fVar22 = (float)__psq_l1(iVar8,uVar16);
            fVar23 = (float)__psq_l0(iVar8 + 8,uVar16);
            fVar27 = (float)__psq_l1(iVar8 + 8,uVar16);
            fVar28 = (float)__psq_l0(iVar8 + 0x10,uVar16);
            fVar30 = (float)__psq_l1(iVar8 + 0x10,uVar16);
            fVar32 = (float)__psq_l0(iVar8 + 0x18,uVar16);
            fVar34 = (float)__psq_l1(iVar8 + 0x18,uVar16);
            fVar35 = (float)__psq_l0(iVar8 + 0x20,uVar16);
            fVar37 = (float)__psq_l1(iVar8 + 0x20,uVar16);
            fVar38 = (float)__psq_l0(iVar8 + 0x28,uVar16);
            fVar39 = (float)__psq_l1(iVar8 + 0x28,uVar16);
            fVar42 = (float)((ulonglong)in_f12 >> 0x20);
            fVar48 = (float)((ulonglong)in_f14 >> 0x20);
            fVar17 = (float)((ulonglong)in_f16 >> 0x20);
            fVar45 = SUB84(in_f12,0);
            fVar49 = SUB84(in_f14,0);
            fVar18 = SUB84(in_f16,0);
            fVar46 = (float)((ulonglong)in_f13 >> 0x20);
            fVar40 = fVar35 * fVar46 + fVar28 * fVar45 + fVar20 * fVar42;
            fVar41 = fVar37 * fVar46 + fVar30 * fVar45 + fVar22 * fVar42;
            in_f12 = (double)CONCAT44(fVar40,fVar41);
            fVar15 = (float)((ulonglong)in_f15 >> 0x20);
            fVar43 = fVar35 * fVar15 + fVar28 * fVar49 + fVar20 * fVar48;
            fVar44 = fVar37 * fVar15 + fVar30 * fVar49 + fVar22 * fVar48;
            in_f14 = (double)CONCAT44(fVar43,fVar44);
            fVar19 = (float)((ulonglong)in_f17 >> 0x20);
            fVar28 = fVar35 * fVar19 + fVar28 * fVar18 + fVar20 * fVar17;
            fVar22 = fVar37 * fVar19 + fVar30 * fVar18 + fVar22 * fVar17;
            in_f16 = (double)CONCAT44(fVar28,fVar22);
            fVar20 = fVar50 * SUB84(in_f13,0) + fVar38 * fVar46 + fVar32 * fVar45 + fVar23 * fVar42;
            fVar42 = fVar51 * SUB84(in_f13,0) + fVar39 * fVar46 + fVar34 * fVar45 + fVar27 * fVar42;
            fVar45 = fVar50 * SUB84(in_f15,0) + fVar38 * fVar15 + fVar32 * fVar49 + fVar23 * fVar48;
            fVar46 = fVar51 * SUB84(in_f15,0) + fVar39 * fVar15 + fVar34 * fVar49 + fVar27 * fVar48;
            in_f15 = (double)CONCAT44(fVar45,fVar46);
            fVar48 = fVar50 * SUB84(in_f17,0) + fVar38 * fVar19 + fVar32 * fVar18 + fVar23 * fVar17;
            fVar49 = fVar51 * SUB84(in_f17,0) + fVar39 * fVar19 + fVar34 * fVar18 + fVar27 * fVar17;
            in_f17 = (double)CONCAT44(fVar48,fVar49);
            __psq_st0(iVar8,fVar40,uVar16);
            __psq_st1(iVar8,fVar41,uVar16);
            __psq_st0(iVar8 + 8,fVar20,uVar16);
            __psq_st1(iVar8 + 8,fVar42,uVar16);
            __psq_st0(iVar8 + 0x10,fVar43,uVar16);
            __psq_st1(iVar8 + 0x10,fVar44,uVar16);
            __psq_st0(iVar8 + 0x18,fVar45,uVar16);
            __psq_st1(iVar8 + 0x18,fVar46,uVar16);
            __psq_st0(iVar8 + 0x20,fVar28,uVar16);
            __psq_st1(iVar8 + 0x20,fVar22,uVar16);
            __psq_st0(iVar8 + 0x28,fVar48,uVar16);
            __psq_st1(iVar8 + 0x28,fVar49,uVar16);
            param_5 = param_5 + -1;
            uVar5 = uVar4;
            dVar13 = in_f13;
            dVar54 = (double)CONCAT44(fVar20,fVar42);
            if (param_5 == 0) {
              return in_f13;
            }
          }
          uVar5 = 0xffffffff;
        }
      }
    }
    else {
      if ((param_8 & 2) == 0) {
        FUN_800074ec();
      }
      __psq_l0(param_3 + 0x58,uVar12);
      dVar13 = (double)FUN_80006e34();
    }
  }
  else {
    dVar54 = (double)*(float *)(param_3 + 4);
    FUN_80007738();
    __psq_st0(local_f0,(int)((ulonglong)dVar54 >> 0x20),uVar10);
    uVar16 = __psq_l0(local_f0,uVar10);
    __psq_st0(local_f0,(int)((ulonglong)
                             (double)(FLOAT_803de50c *
                                     (float)(dVar54 - (double)CONCAT44(uVar16,0x3f800000))) >> 0x20)
              ,uVar10);
    FUN_80006e34();
    FUN_800074ec();
    __psq_l0(param_3 + 0x58,uVar12);
    dVar13 = (double)FUN_80006e34();
  }
  return dVar13;
}

