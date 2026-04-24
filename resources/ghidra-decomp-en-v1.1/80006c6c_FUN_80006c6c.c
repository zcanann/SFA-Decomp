// Function: FUN_80006c6c
// Entry: 80006c6c
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x80006e08) */
/* WARNING: Removing unreachable block (ram,0x80006dcc) */
/* WARNING: Removing unreachable block (ram,0x80006dbc) */
/* WARNING: Removing unreachable block (ram,0x80006db8) */
/* WARNING: Removing unreachable block (ram,0x80006d74) */
/* WARNING: Removing unreachable block (ram,0x80007e54) */
/* WARNING: Removing unreachable block (ram,0x80007e5c) */
/* WARNING: Removing unreachable block (ram,0x80007e94) */
/* WARNING: Removing unreachable block (ram,0x80007e50) */
/* WARNING: Removing unreachable block (ram,0x80007e8c) */
/* WARNING: Removing unreachable block (ram,0x80007e80) */
/* WARNING: Removing unreachable block (ram,0x80007e4c) */
/* WARNING: Removing unreachable block (ram,0x80007d7c) */
/* WARNING: Removing unreachable block (ram,0x80007bf4) */
/* WARNING: Removing unreachable block (ram,0x80007cfc) */
/* WARNING: Removing unreachable block (ram,0x80007b4c) */
/* WARNING: Removing unreachable block (ram,0x80007c08) */
/* WARNING: Removing unreachable block (ram,0x80007be0) */
/* WARNING: Removing unreachable block (ram,0x80007ad0) */
/* WARNING: Removing unreachable block (ram,0x80007a54) */
/* WARNING: Removing unreachable block (ram,0x80007cbc) */
/* WARNING: Removing unreachable block (ram,0x80007e90) */
/* WARNING: Removing unreachable block (ram,0x80007e58) */
/* WARNING: Removing unreachable block (ram,0x80007e84) */
/* WARNING: Removing unreachable block (ram,0x80007d40) */
/* WARNING: Removing unreachable block (ram,0x80007e60) */
/* WARNING: Removing unreachable block (ram,0x80007e88) */

void FUN_80006c6c(int *param_1,float *param_2,int param_3,undefined4 param_4,int param_5,int param_6
                 ,uint param_7,uint param_8)

{
  float *pfVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  byte bVar11;
  byte bVar12;
  byte bVar13;
  longlong lVar14;
  byte bVar15;
  byte bVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  int unaff_r2;
  int iVar21;
  undefined uVar22;
  undefined extraout_r4;
  undefined4 uVar23;
  int iVar24;
  undefined uVar25;
  undefined *puVar26;
  int unaff_r13;
  uint uVar27;
  ushort uVar28;
  short sVar29;
  uint uVar30;
  byte *pbVar31;
  short *psVar32;
  float *pfVar33;
  int iVar34;
  uint unaff_GQR0;
  uint unaff_GQR3;
  uint unaff_GQR5;
  double dVar35;
  double dVar36;
  double dVar37;
  double dVar38;
  double dVar39;
  double in_f12;
  double in_f13;
  double dVar40;
  double in_f14;
  double in_f15;
  double dVar41;
  double in_f16;
  double in_f17;
  double dVar42;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double dVar43;
  double dVar44;
  double in_f31;
  double dVar45;
  double dVar46;
  double dVar47;
  double dVar48;
  double dVar49;
  double dVar50;
  double in_ps12_1;
  double dVar51;
  double in_ps13_1;
  double dVar52;
  double in_ps14_1;
  double dVar53;
  double in_ps15_1;
  double dVar54;
  double in_ps16_1;
  double in_ps17_1;
  undefined8 uVar55;
  undefined *in_stack_ffffff0c;
  float in_stack_ffffff10;
  float fVar56;
  float fVar57;
  
  *(int **)(unaff_r13 + -0x7ffc) = param_1;
  iVar21 = *param_1;
  *(int *)(unaff_r13 + -0x8000) = iVar21;
  *(undefined4 *)(unaff_r13 + -0x6a20) = param_4;
  dVar44 = (double)*(float *)(unaff_r2 + -0x7ff8);
  bVar11 = (byte)(unaff_GQR5 >> 0x10);
  bVar13 = (byte)(unaff_GQR5 >> 0x18);
  bVar12 = (byte)(unaff_GQR3 >> 0x10);
  bVar15 = (byte)(unaff_GQR3 >> 0x18);
  if ((param_8 & 0x40) == 0) {
    if ((param_8 & 1) == 0) {
      puVar26 = &DAT_802c3d00;
      param_4 = *(undefined4 *)(param_3 + 0x34);
      uVar55 = FUN_800074ec((char)iVar21,(char)param_2,(char)param_3,(char)param_4,(char)param_5,
                            (char)param_6,(char)param_7,(char)param_8,0,in_stack_ffffff10);
      iVar21 = (int)((ulonglong)uVar55 >> 0x20);
      param_2 = (float *)uVar55;
      in_stack_ffffff0c = puVar26;
      if (*(short *)(param_3 + 0x58) < 1) {
        iVar21 = *(int *)(unaff_r13 + -0x6a20);
        iVar24 = *(int *)(unaff_r13 + -0x8000);
        iVar34 = param_5 * 0x1c + iVar21;
        dVar42 = (double)*(float *)(unaff_r2 + -0x7fe4);
        dVar43 = (double)*(float *)(unaff_r2 + -0x7fe8);
        do {
          while (uVar27 = (int)*(char *)(iVar21 + 1) & param_7, -1 < (int)uVar27) {
            pfVar33 = (float *)(uVar27 * 0x40 + iVar24);
            psVar32 = (short *)(puVar26 + (uint)*(byte *)(iVar21 + 2) * 0x40);
            DAT_803364a0 = (float)in_f23;
            DAT_803364a4 = (float)in_f24;
            DAT_803364a8 = (float)in_f25;
            DAT_803364ac = (float)in_f26;
            DAT_803364b0 = (float)in_f27;
            DAT_803364b4 = (float)in_f28;
            DAT_803364b8 = (float)dVar43;
            DAT_803364bc = (float)dVar44;
            DAT_803364c0 = (float)in_f31;
            fVar56 = *(float *)(unaff_r2 + -0x7fe0);
            fVar57 = *(float *)(unaff_r2 + -0x7fdc);
            fVar4 = *(float *)(unaff_r2 + -0x7fd8);
            fVar5 = *(float *)(unaff_r2 + -0x7fd4);
            fVar6 = *(float *)(unaff_r2 + -0x7fd0);
            fVar7 = *(float *)(unaff_r2 + -0x7fcc);
            fVar8 = *(float *)(unaff_r2 + -0x7fc8);
            fVar9 = *(float *)(unaff_r2 + -0x7fc4);
            fVar10 = *(float *)(unaff_r2 + -0x7fc0);
            sVar29 = *psVar32 << 2;
            DAT_803364c4 = (float)CONCAT22(sVar29,DAT_803364c4._2_2_);
            bVar16 = bVar11 & 7;
            if ((unaff_GQR5 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar16 == 4 || bVar16 == 6) {
              DAT_803364c4._0_1_ = (char)((ushort)sVar29 >> 8);
              dVar44 = (double)(lVar14 * (longlong)(double)DAT_803364c4._0_1_);
            }
            else if (bVar16 == 5 || bVar16 == 7) {
              dVar44 = (double)(lVar14 * (longlong)(double)sVar29);
            }
            else {
              dVar44 = (double)DAT_803364c4;
            }
            fVar2 = (float)(dVar44 * dVar44);
            dVar35 = (double)(float)(dVar44 * (double)(fVar2 * (fVar2 * (fVar2 * fVar7 + fVar8) +
                                                               fVar9) + fVar10));
            dVar44 = (double)(fVar2 * (fVar2 * (fVar2 * (fVar2 * fVar56 + fVar57) + fVar4) + fVar5)
                             + fVar6);
            uVar28 = *psVar32 + 0x2000U & 0xc000;
            dVar45 = dVar44;
            if (uVar28 != 0) {
              if (uVar28 == 0x4000) {
                dVar45 = -dVar35;
                dVar35 = dVar44;
              }
              else if (uVar28 == 0x8000) {
                dVar45 = -dVar44;
                dVar35 = -dVar35;
              }
              else {
                dVar45 = dVar35;
                dVar35 = -dVar44;
              }
            }
            sVar29 = psVar32[1] << 2;
            DAT_803364c4 = (float)CONCAT22(sVar29,DAT_803364c4._2_2_);
            bVar16 = bVar11 & 7;
            if ((unaff_GQR5 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar16 == 4 || bVar16 == 6) {
              DAT_803364c4._0_1_ = (char)((ushort)sVar29 >> 8);
              dVar44 = (double)(lVar14 * (longlong)(double)DAT_803364c4._0_1_);
            }
            else if (bVar16 == 5 || bVar16 == 7) {
              dVar44 = (double)(lVar14 * (longlong)(double)sVar29);
            }
            else {
              dVar44 = (double)DAT_803364c4;
            }
            fVar2 = (float)(dVar44 * dVar44);
            dVar36 = (double)(float)(dVar44 * (double)(fVar2 * (fVar2 * (fVar2 * fVar7 + fVar8) +
                                                               fVar9) + fVar10));
            dVar44 = (double)(fVar2 * (fVar2 * (fVar2 * (fVar2 * fVar56 + fVar57) + fVar4) + fVar5)
                             + fVar6);
            uVar28 = psVar32[1] + 0x2000U & 0xc000;
            dVar46 = dVar44;
            if (uVar28 != 0) {
              if (uVar28 == 0x4000) {
                dVar46 = -dVar36;
                dVar36 = dVar44;
              }
              else if (uVar28 == 0x8000) {
                dVar46 = -dVar44;
                dVar36 = -dVar36;
              }
              else {
                dVar46 = dVar36;
                dVar36 = -dVar44;
              }
            }
            sVar29 = psVar32[2] << 2;
            DAT_803364c4 = (float)CONCAT22(sVar29,DAT_803364c4._2_2_);
            fVar2 = DAT_803364c4;
            bVar16 = bVar11 & 7;
            if ((unaff_GQR5 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar16 == 4 || bVar16 == 6) {
              DAT_803364c4._0_1_ = (char)((ushort)sVar29 >> 8);
              dVar44 = (double)(lVar14 * (longlong)(double)DAT_803364c4._0_1_);
            }
            else if (bVar16 == 5 || bVar16 == 7) {
              dVar44 = (double)(lVar14 * (longlong)(double)sVar29);
            }
            else {
              dVar44 = (double)DAT_803364c4;
            }
            fVar3 = (float)(dVar44 * dVar44);
            dVar37 = (double)(float)(dVar44 * (double)(fVar3 * (fVar3 * (fVar3 * fVar7 + fVar8) +
                                                               fVar9) + fVar10));
            dVar44 = (double)(fVar3 * (fVar3 * (fVar3 * (fVar3 * fVar56 + fVar57) + fVar4) + fVar5)
                             + fVar6);
            uVar28 = psVar32[2] + 0x2000U & 0xc000;
            dVar47 = dVar44;
            if (uVar28 != 0) {
              if (uVar28 == 0x4000) {
                dVar47 = -dVar37;
                dVar37 = dVar44;
              }
              else if (uVar28 == 0x8000) {
                dVar47 = -dVar44;
                dVar37 = -dVar37;
              }
              else {
                dVar47 = dVar37;
                dVar37 = -dVar44;
              }
            }
            in_f23 = (double)DAT_803364a0;
            in_f24 = (double)DAT_803364a4;
            in_f25 = (double)DAT_803364a8;
            in_f26 = (double)DAT_803364ac;
            in_f27 = (double)DAT_803364b0;
            in_f28 = (double)DAT_803364b4;
            dVar43 = (double)DAT_803364b8;
            dVar44 = (double)DAT_803364bc;
            in_f31 = (double)DAT_803364c0;
            pfVar1 = (float *)(psVar32 + 0xc);
            bVar16 = bVar11 & 7;
            if ((unaff_GQR5 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar16 == 4 || bVar16 == 6) {
              dVar48 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            }
            else if (bVar16 == 5 || bVar16 == 7) {
              dVar48 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            }
            else {
              dVar48 = (double)*pfVar1;
            }
            DAT_803364c4 = fVar2;
            pfVar33[3] = *(float *)(iVar21 + 4) + (float)(dVar48 * dVar43);
            pfVar1 = (float *)(psVar32 + 0xd);
            bVar16 = bVar11 & 7;
            if ((unaff_GQR5 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar16 == 4 || bVar16 == 6) {
              dVar48 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            }
            else if (bVar16 == 5 || bVar16 == 7) {
              dVar48 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            }
            else {
              dVar48 = (double)*pfVar1;
            }
            pfVar33[7] = *(float *)(iVar21 + 8) + (float)(dVar48 * dVar43);
            pfVar1 = (float *)(psVar32 + 0xe);
            bVar16 = bVar11 & 7;
            if ((unaff_GQR5 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar16 == 4 || bVar16 == 6) {
              dVar48 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            }
            else if (bVar16 == 5 || bVar16 == 7) {
              dVar48 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            }
            else {
              dVar48 = (double)*pfVar1;
            }
            dVar38 = (double)(float)(dVar45 * dVar37);
            pfVar33[0xb] = *(float *)(iVar21 + 0xc) + (float)(dVar48 * dVar43);
            dVar48 = (double)(float)(dVar35 * dVar37);
            dVar49 = (double)(float)(dVar35 * dVar47);
            dVar50 = (double)(float)(dVar45 * dVar47);
            in_f12 = (double)(float)(dVar46 * dVar47);
            sVar29 = psVar32[6];
            in_f13 = (double)(float)(dVar46 * dVar37);
            if (sVar29 == 0) {
              *pfVar33 = (float)(dVar46 * dVar47);
              in_f14 = (double)(float)(dVar44 - dVar36);
              pfVar33[4] = (float)(dVar46 * dVar37);
LAB_80007c4c:
              pfVar33[8] = (float)in_f14;
              fVar56 = (float)((double)(float)(dVar49 * dVar36) - dVar38);
              in_f15 = (double)fVar56;
              sVar29 = psVar32[7];
              dVar47 = (double)(float)(dVar48 * dVar36);
              if (sVar29 != 0) goto LAB_80007cf8;
              pfVar33[1] = fVar56;
              in_f16 = (double)(float)(dVar47 + dVar50);
              in_f17 = (double)(float)(dVar35 * dVar46);
              pfVar33[5] = (float)(dVar47 + dVar50);
LAB_80007c78:
              pfVar33[9] = (float)in_f17;
              fVar56 = (float)((double)(float)(dVar50 * dVar36) + dVar48);
              sVar29 = psVar32[8];
              dVar35 = (double)(float)(dVar38 * dVar36);
              if (sVar29 != 0) goto LAB_80007d3c;
              pfVar33[2] = fVar56;
              pfVar33[6] = (float)(dVar35 - dVar49);
              pfVar33[10] = (float)(dVar45 * dVar46);
            }
            else {
              in_stack_ffffff10 = (float)CONCAT22(sVar29,SUB42(in_stack_ffffff10,0));
              bVar16 = bVar12 & 7;
              if ((unaff_GQR3 & 0x3f000000) == 0) {
                lVar14 = 0x3ff0000000000000;
              }
              else {
                lVar14 = ldexpf(-(bVar15 & 0x3f));
              }
              if (bVar16 == 4 || bVar16 == 6) {
                dVar47 = (double)(lVar14 * (longlong)(double)(char)((ushort)sVar29 >> 8));
              }
              else if (bVar16 == 5 || bVar16 == 7) {
                dVar47 = (double)(lVar14 * (longlong)(double)sVar29);
              }
              else {
                dVar47 = (double)in_stack_ffffff10;
              }
              dVar37 = (double)(float)(dVar47 * dVar42);
              dVar47 = in_f12 * dVar37;
              in_f12 = (double)(float)dVar47;
              *pfVar33 = (float)dVar47;
              dVar47 = in_f13 * dVar37;
              in_f13 = (double)(float)dVar47;
              sVar29 = psVar32[7];
              fVar56 = (float)((double)(float)(dVar44 - dVar36) * dVar37);
              in_f14 = (double)fVar56;
              pfVar33[4] = (float)dVar47;
              if (sVar29 == 0) goto LAB_80007c4c;
              pfVar33[8] = fVar56;
              in_f15 = (double)(float)((double)(float)(dVar49 * dVar36) - dVar38);
              dVar47 = (double)(float)(dVar48 * dVar36);
LAB_80007cf8:
              in_stack_ffffff10 = (float)CONCAT22(sVar29,SUB42(in_stack_ffffff10,0));
              bVar16 = bVar12 & 7;
              if ((unaff_GQR3 & 0x3f000000) == 0) {
                lVar14 = 0x3ff0000000000000;
              }
              else {
                lVar14 = ldexpf(-(bVar15 & 0x3f));
              }
              if (bVar16 == 4 || bVar16 == 6) {
                dVar37 = (double)(lVar14 * (longlong)(double)(char)((ushort)sVar29 >> 8));
              }
              else if (bVar16 == 5 || bVar16 == 7) {
                dVar37 = (double)(lVar14 * (longlong)(double)sVar29);
              }
              else {
                dVar37 = (double)in_stack_ffffff10;
              }
              dVar39 = (double)(float)(dVar37 * dVar42);
              dVar37 = in_f15 * dVar39;
              in_f15 = (double)(float)dVar37;
              pfVar33[1] = (float)dVar37;
              fVar56 = (float)((double)(float)(dVar47 + dVar50) * dVar39);
              in_f16 = (double)fVar56;
              sVar29 = psVar32[8];
              fVar57 = (float)((double)(float)(dVar35 * dVar46) * dVar39);
              in_f17 = (double)fVar57;
              pfVar33[5] = fVar56;
              if (sVar29 == 0) goto LAB_80007c78;
              pfVar33[9] = fVar57;
              fVar56 = (float)((double)(float)(dVar50 * dVar36) + dVar48);
              dVar35 = (double)(float)(dVar38 * dVar36);
LAB_80007d3c:
              in_stack_ffffff10 = (float)CONCAT22(sVar29,SUB42(in_stack_ffffff10,0));
              bVar16 = bVar12 & 7;
              if ((unaff_GQR3 & 0x3f000000) == 0) {
                lVar14 = 0x3ff0000000000000;
              }
              else {
                lVar14 = ldexpf(-(bVar15 & 0x3f));
              }
              if (bVar16 == 4 || bVar16 == 6) {
                dVar36 = (double)(lVar14 * (longlong)(double)(char)((ushort)sVar29 >> 8));
              }
              else if (bVar16 == 5 || bVar16 == 7) {
                dVar36 = (double)(lVar14 * (longlong)(double)sVar29);
              }
              else {
                dVar36 = (double)in_stack_ffffff10;
              }
              fVar57 = (float)(dVar36 * dVar42);
              pfVar33[2] = fVar56 * fVar57;
              pfVar33[6] = (float)(dVar35 - dVar49) * fVar57;
              pfVar33[10] = (float)(dVar45 * dVar46) * fVar57;
            }
            iVar21 = iVar21 + 0x1c;
            in_ps12_1 = in_f12;
            in_ps13_1 = in_f13;
            in_ps14_1 = in_f14;
            in_ps15_1 = in_f15;
            in_ps16_1 = in_f16;
            in_ps17_1 = in_f17;
            if (iVar21 == iVar34) goto LAB_80007d74;
          }
          iVar21 = iVar21 + 0x1c;
        } while (iVar21 != iVar34);
LAB_80007d74:
        bVar11 = (byte)(unaff_GQR0 >> 0x10);
        bVar12 = bVar11 & 7;
        bVar13 = (byte)(unaff_GQR0 >> 0x18);
        if ((unaff_GQR0 & 0x3f000000) == 0) {
          lVar14 = 0x3ff0000000000000;
        }
        else {
          lVar14 = ldexpf(-(bVar13 & 0x3f));
        }
        if (bVar12 == 4 || bVar12 == 6) {
          dVar44 = (double)(lVar14 * (longlong)(double)DAT_803df180._0_1_);
          dVar42 = (double)(lVar14 * (longlong)(double)DAT_803df180._1_1_);
        }
        else if (bVar12 == 5 || bVar12 == 7) {
          dVar44 = (double)(lVar14 * (longlong)(double)DAT_803df180._0_2_);
          dVar42 = (double)(lVar14 * (longlong)(double)DAT_803df180._2_2_);
        }
        else {
          dVar44 = (double)DAT_803df180;
          dVar42 = (double)DAT_803df184;
        }
        if ((param_8 & 0xc) != 0) {
          return;
        }
        iVar21 = *(int *)(unaff_r13 + -0x8000);
        pbVar31 = *(byte **)(unaff_r13 + -0x6a20);
        uVar27 = (int)(char)pbVar31[1] & 0x7f;
        pfVar33 = (float *)(uVar27 * 0x40 + iVar21);
        if (-1 < (int)((int)(char)pbVar31[1] & param_7)) goto LAB_80007e4c;
        uVar30 = 0xfffffffb;
        do {
          param_5 = param_5 + -1;
          if (param_5 == 0) {
            return;
          }
          while( true ) {
            pbVar31 = pbVar31 + 0x1c;
            uVar27 = (int)(char)pbVar31[1] & param_7;
            if (-1 < (int)uVar27) break;
            uVar30 = 0xffffffff;
            param_5 = param_5 + -1;
            if (param_5 == 0) {
              return;
            }
          }
          pfVar33 = (float *)(uVar27 * 0x40 + iVar21);
          if (*pbVar31 != uVar30) {
            param_2 = (float *)((uint)*pbVar31 * 0x40 + iVar21);
LAB_80007e4c:
            bVar12 = bVar11 & 7;
            if ((unaff_GQR0 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar12 == 4 || bVar12 == 6) {
              in_f12 = (double)(lVar14 * (longlong)(double)*(char *)param_2);
              in_ps12_1 = (double)(lVar14 * (longlong)(double)*(char *)((int)param_2 + 1));
            }
            else if (bVar12 == 5 || bVar12 == 7) {
              in_f12 = (double)(lVar14 * (longlong)(double)*(short *)param_2);
              in_ps12_1 = (double)(lVar14 * (longlong)(double)*(short *)((int)param_2 + 2));
            }
            else {
              in_f12 = (double)*param_2;
              in_ps12_1 = (double)param_2[1];
            }
            pfVar1 = param_2 + 2;
            bVar12 = bVar11 & 7;
            if ((unaff_GQR0 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar12 == 4 || bVar12 == 6) {
              in_f13 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
              in_ps13_1 = (double)(lVar14 * (longlong)(double)*(char *)((int)param_2 + 9));
            }
            else if (bVar12 == 5 || bVar12 == 7) {
              in_f13 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
              in_ps13_1 = (double)(lVar14 * (longlong)(double)*(short *)((int)param_2 + 10));
            }
            else {
              in_f13 = (double)*pfVar1;
              in_ps13_1 = (double)param_2[3];
            }
            pfVar1 = param_2 + 4;
            bVar12 = bVar11 & 7;
            if ((unaff_GQR0 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar12 == 4 || bVar12 == 6) {
              in_f14 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
              in_ps14_1 = (double)(lVar14 * (longlong)(double)*(char *)((int)param_2 + 0x11));
            }
            else if (bVar12 == 5 || bVar12 == 7) {
              in_f14 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
              in_ps14_1 = (double)(lVar14 * (longlong)(double)*(short *)((int)param_2 + 0x12));
            }
            else {
              in_f14 = (double)*pfVar1;
              in_ps14_1 = (double)param_2[5];
            }
            pfVar1 = param_2 + 6;
            bVar12 = bVar11 & 7;
            if ((unaff_GQR0 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar12 == 4 || bVar12 == 6) {
              in_f15 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
              in_ps15_1 = (double)(lVar14 * (longlong)(double)*(char *)((int)param_2 + 0x19));
            }
            else if (bVar12 == 5 || bVar12 == 7) {
              in_f15 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
              in_ps15_1 = (double)(lVar14 * (longlong)(double)*(short *)((int)param_2 + 0x1a));
            }
            else {
              in_f15 = (double)*pfVar1;
              in_ps15_1 = (double)param_2[7];
            }
            pfVar1 = param_2 + 8;
            bVar12 = bVar11 & 7;
            if ((unaff_GQR0 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar12 == 4 || bVar12 == 6) {
              in_f16 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
              in_ps16_1 = (double)(lVar14 * (longlong)(double)*(char *)((int)param_2 + 0x21));
            }
            else if (bVar12 == 5 || bVar12 == 7) {
              in_f16 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
              in_ps16_1 = (double)(lVar14 * (longlong)(double)*(short *)((int)param_2 + 0x22));
            }
            else {
              in_f16 = (double)*pfVar1;
              in_ps16_1 = (double)param_2[9];
            }
            pfVar1 = param_2 + 10;
            bVar12 = bVar11 & 7;
            if ((unaff_GQR0 & 0x3f000000) == 0) {
              lVar14 = 0x3ff0000000000000;
            }
            else {
              lVar14 = ldexpf(-(bVar13 & 0x3f));
            }
            if (bVar12 == 4 || bVar12 == 6) {
              in_f17 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
              in_ps17_1 = (double)(lVar14 * (longlong)(double)*(char *)((int)param_2 + 0x29));
            }
            else if (bVar12 == 5 || bVar12 == 7) {
              in_f17 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
              in_ps17_1 = (double)(lVar14 * (longlong)(double)*(short *)((int)param_2 + 0x2a));
            }
            else {
              in_f17 = (double)*pfVar1;
              in_ps17_1 = (double)param_2[0xb];
            }
          }
          bVar12 = bVar11 & 7;
          if ((unaff_GQR0 & 0x3f000000) == 0) {
            lVar14 = 0x3ff0000000000000;
          }
          else {
            lVar14 = ldexpf(-(bVar13 & 0x3f));
          }
          if (bVar12 == 4 || bVar12 == 6) {
            dVar43 = (double)(lVar14 * (longlong)(double)*(char *)pfVar33);
            dVar45 = (double)(lVar14 * (longlong)(double)*(char *)((int)pfVar33 + 1));
          }
          else if (bVar12 == 5 || bVar12 == 7) {
            dVar43 = (double)(lVar14 * (longlong)(double)*(short *)pfVar33);
            dVar45 = (double)(lVar14 * (longlong)(double)*(short *)((int)pfVar33 + 2));
          }
          else {
            dVar43 = (double)*pfVar33;
            dVar45 = (double)pfVar33[1];
          }
          pfVar1 = pfVar33 + 2;
          bVar12 = bVar11 & 7;
          if ((unaff_GQR0 & 0x3f000000) == 0) {
            lVar14 = 0x3ff0000000000000;
          }
          else {
            lVar14 = ldexpf(-(bVar13 & 0x3f));
          }
          if (bVar12 == 4 || bVar12 == 6) {
            dVar35 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            dVar46 = (double)(lVar14 * (longlong)(double)*(char *)((int)pfVar33 + 9));
          }
          else if (bVar12 == 5 || bVar12 == 7) {
            dVar35 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            dVar46 = (double)(lVar14 * (longlong)(double)*(short *)((int)pfVar33 + 10));
          }
          else {
            dVar35 = (double)*pfVar1;
            dVar46 = (double)pfVar33[3];
          }
          pfVar1 = pfVar33 + 4;
          bVar12 = bVar11 & 7;
          if ((unaff_GQR0 & 0x3f000000) == 0) {
            lVar14 = 0x3ff0000000000000;
          }
          else {
            lVar14 = ldexpf(-(bVar13 & 0x3f));
          }
          if (bVar12 == 4 || bVar12 == 6) {
            dVar36 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            dVar47 = (double)(lVar14 * (longlong)(double)*(char *)((int)pfVar33 + 0x11));
          }
          else if (bVar12 == 5 || bVar12 == 7) {
            dVar36 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            dVar47 = (double)(lVar14 * (longlong)(double)*(short *)((int)pfVar33 + 0x12));
          }
          else {
            dVar36 = (double)*pfVar1;
            dVar47 = (double)pfVar33[5];
          }
          pfVar1 = pfVar33 + 6;
          bVar12 = bVar11 & 7;
          if ((unaff_GQR0 & 0x3f000000) == 0) {
            lVar14 = 0x3ff0000000000000;
          }
          else {
            lVar14 = ldexpf(-(bVar13 & 0x3f));
          }
          if (bVar12 == 4 || bVar12 == 6) {
            dVar37 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            dVar48 = (double)(lVar14 * (longlong)(double)*(char *)((int)pfVar33 + 0x19));
          }
          else if (bVar12 == 5 || bVar12 == 7) {
            dVar37 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            dVar48 = (double)(lVar14 * (longlong)(double)*(short *)((int)pfVar33 + 0x1a));
          }
          else {
            dVar37 = (double)*pfVar1;
            dVar48 = (double)pfVar33[7];
          }
          pfVar1 = pfVar33 + 8;
          bVar12 = bVar11 & 7;
          if ((unaff_GQR0 & 0x3f000000) == 0) {
            lVar14 = 0x3ff0000000000000;
          }
          else {
            lVar14 = ldexpf(-(bVar13 & 0x3f));
          }
          if (bVar12 == 4 || bVar12 == 6) {
            dVar38 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            dVar49 = (double)(lVar14 * (longlong)(double)*(char *)((int)pfVar33 + 0x21));
          }
          else if (bVar12 == 5 || bVar12 == 7) {
            dVar38 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            dVar49 = (double)(lVar14 * (longlong)(double)*(short *)((int)pfVar33 + 0x22));
          }
          else {
            dVar38 = (double)*pfVar1;
            dVar49 = (double)pfVar33[9];
          }
          pfVar1 = pfVar33 + 10;
          bVar12 = bVar11 & 7;
          if ((unaff_GQR0 & 0x3f000000) == 0) {
            lVar14 = 0x3ff0000000000000;
          }
          else {
            lVar14 = ldexpf(-(bVar13 & 0x3f));
          }
          if (bVar12 == 4 || bVar12 == 6) {
            dVar39 = (double)(lVar14 * (longlong)(double)*(char *)pfVar1);
            dVar50 = (double)(lVar14 * (longlong)(double)*(char *)((int)pfVar33 + 0x29));
          }
          else if (bVar12 == 5 || bVar12 == 7) {
            dVar39 = (double)(lVar14 * (longlong)(double)*(short *)pfVar1);
            dVar50 = (double)(lVar14 * (longlong)(double)*(short *)((int)pfVar33 + 0x2a));
          }
          else {
            dVar39 = (double)*pfVar1;
            dVar50 = (double)pfVar33[0xb];
          }
          dVar51 = dVar45 * in_f12;
          dVar40 = dVar35 * in_f12;
          dVar52 = dVar46 * in_f12;
          dVar53 = dVar45 * in_f14;
          dVar41 = dVar35 * in_f14;
          dVar54 = dVar46 * in_f14;
          dVar45 = dVar45 * in_f16;
          dVar35 = dVar35 * in_f16;
          dVar46 = dVar46 * in_f16;
          dVar17 = dVar37 * in_ps12_1;
          dVar19 = dVar48 * in_ps12_1;
          dVar18 = dVar37 * in_ps14_1;
          dVar20 = dVar48 * in_ps14_1;
          dVar37 = dVar37 * in_ps16_1;
          dVar48 = dVar48 * in_ps16_1;
          in_f12 = dVar38 * in_f13 + dVar36 * in_ps12_1 + dVar43 * in_f12;
          in_ps12_1 = dVar49 * in_f13 + dVar47 * in_ps12_1 + dVar51;
          dVar51 = dVar50 * in_f13;
          in_f14 = dVar38 * in_f15 + dVar36 * in_ps14_1 + dVar43 * in_f14;
          in_ps14_1 = dVar49 * in_f15 + dVar47 * in_ps14_1 + dVar53;
          dVar53 = dVar50 * in_f15;
          in_f16 = dVar38 * in_f17 + dVar36 * in_ps16_1 + dVar43 * in_f16;
          in_ps16_1 = dVar49 * in_f17 + dVar47 * in_ps16_1 + dVar45;
          dVar50 = dVar50 * in_f17;
          in_f13 = dVar44 * in_ps13_1 + dVar39 * in_f13 + dVar17 + dVar40;
          in_ps13_1 = dVar42 * in_ps13_1 + dVar51 + dVar19 + dVar52;
          in_f15 = dVar44 * in_ps15_1 + dVar39 * in_f15 + dVar18 + dVar41;
          in_ps15_1 = dVar42 * in_ps15_1 + dVar53 + dVar20 + dVar54;
          in_f17 = dVar44 * in_ps17_1 + dVar39 * in_f17 + dVar37 + dVar35;
          in_ps17_1 = dVar42 * in_ps17_1 + dVar50 + dVar48 + dVar46;
          bVar12 = (byte)unaff_GQR0;
          bVar15 = bVar12 & 7;
          bVar16 = (byte)(unaff_GQR0 >> 8);
          if ((unaff_GQR0 & 0x3f00) == 0) {
            dVar43 = 1.0;
          }
          else {
            dVar43 = (double)ldexpf(bVar16 & 0x3f);
          }
          if (bVar15 == 4 || bVar15 == 6) {
            *(char *)pfVar33 = (char)(dVar43 * in_f12);
            *(char *)((int)pfVar33 + 1) = (char)(dVar43 * in_ps12_1);
          }
          else if (bVar15 == 5 || bVar15 == 7) {
            *(short *)pfVar33 = (short)(dVar43 * in_f12);
            *(short *)((int)pfVar33 + 2) = (short)(dVar43 * in_ps12_1);
          }
          else {
            *pfVar33 = (float)in_f12;
            pfVar33[1] = (float)in_ps12_1;
          }
          pfVar1 = pfVar33 + 2;
          bVar15 = bVar12 & 7;
          if ((unaff_GQR0 & 0x3f00) == 0) {
            dVar43 = 1.0;
          }
          else {
            dVar43 = (double)ldexpf(bVar16 & 0x3f);
          }
          if (bVar15 == 4 || bVar15 == 6) {
            *(char *)pfVar1 = (char)(dVar43 * in_f13);
            *(char *)((int)pfVar33 + 9) = (char)(dVar43 * in_ps13_1);
          }
          else if (bVar15 == 5 || bVar15 == 7) {
            *(short *)pfVar1 = (short)(dVar43 * in_f13);
            *(short *)((int)pfVar33 + 10) = (short)(dVar43 * in_ps13_1);
          }
          else {
            *pfVar1 = (float)in_f13;
            pfVar33[3] = (float)in_ps13_1;
          }
          pfVar1 = pfVar33 + 4;
          bVar15 = bVar12 & 7;
          if ((unaff_GQR0 & 0x3f00) == 0) {
            dVar43 = 1.0;
          }
          else {
            dVar43 = (double)ldexpf(bVar16 & 0x3f);
          }
          if (bVar15 == 4 || bVar15 == 6) {
            *(char *)pfVar1 = (char)(dVar43 * in_f14);
            *(char *)((int)pfVar33 + 0x11) = (char)(dVar43 * in_ps14_1);
          }
          else if (bVar15 == 5 || bVar15 == 7) {
            *(short *)pfVar1 = (short)(dVar43 * in_f14);
            *(short *)((int)pfVar33 + 0x12) = (short)(dVar43 * in_ps14_1);
          }
          else {
            *pfVar1 = (float)in_f14;
            pfVar33[5] = (float)in_ps14_1;
          }
          pfVar1 = pfVar33 + 6;
          bVar15 = bVar12 & 7;
          if ((unaff_GQR0 & 0x3f00) == 0) {
            dVar43 = 1.0;
          }
          else {
            dVar43 = (double)ldexpf(bVar16 & 0x3f);
          }
          if (bVar15 == 4 || bVar15 == 6) {
            *(char *)pfVar1 = (char)(dVar43 * in_f15);
            *(char *)((int)pfVar33 + 0x19) = (char)(dVar43 * in_ps15_1);
          }
          else if (bVar15 == 5 || bVar15 == 7) {
            *(short *)pfVar1 = (short)(dVar43 * in_f15);
            *(short *)((int)pfVar33 + 0x1a) = (short)(dVar43 * in_ps15_1);
          }
          else {
            *pfVar1 = (float)in_f15;
            pfVar33[7] = (float)in_ps15_1;
          }
          pfVar1 = pfVar33 + 8;
          bVar15 = bVar12 & 7;
          if ((unaff_GQR0 & 0x3f00) == 0) {
            dVar43 = 1.0;
          }
          else {
            dVar43 = (double)ldexpf(bVar16 & 0x3f);
          }
          if (bVar15 == 4 || bVar15 == 6) {
            *(char *)pfVar1 = (char)(dVar43 * in_f16);
            *(char *)((int)pfVar33 + 0x21) = (char)(dVar43 * in_ps16_1);
          }
          else if (bVar15 == 5 || bVar15 == 7) {
            *(short *)pfVar1 = (short)(dVar43 * in_f16);
            *(short *)((int)pfVar33 + 0x22) = (short)(dVar43 * in_ps16_1);
          }
          else {
            *pfVar1 = (float)in_f16;
            pfVar33[9] = (float)in_ps16_1;
          }
          pfVar1 = pfVar33 + 10;
          bVar12 = bVar12 & 7;
          if ((unaff_GQR0 & 0x3f00) == 0) {
            dVar43 = 1.0;
          }
          else {
            dVar43 = (double)ldexpf(bVar16 & 0x3f);
          }
          uVar30 = uVar27;
          if (bVar12 == 4 || bVar12 == 6) {
            *(char *)pfVar1 = (char)(dVar43 * in_f17);
            *(char *)((int)pfVar33 + 0x29) = (char)(dVar43 * in_ps17_1);
          }
          else if (bVar12 == 5 || bVar12 == 7) {
            *(short *)pfVar1 = (short)(dVar43 * in_f17);
            *(short *)((int)pfVar33 + 0x2a) = (short)(dVar43 * in_ps17_1);
          }
          else {
            *pfVar1 = (float)in_f17;
            pfVar33[0xb] = (float)in_ps17_1;
          }
        } while( true );
      }
    }
    else {
      puVar26 = (undefined *)(iVar21 + 0x1c);
    }
    uVar55 = CONCAT44(iVar21,param_2);
    if ((param_8 & 2) == 0) {
      param_4 = *(undefined4 *)(param_3 + 0x38);
      param_6 = param_6 + 2;
      uVar55 = FUN_800074ec((char)iVar21,(char)param_2,(char)param_3,(char)param_4,(char)param_5,
                            (char)param_6,(char)param_7,(char)param_8,(char)puVar26,
                            in_stack_ffffff10);
      in_stack_ffffff0c = puVar26;
    }
    if ((unaff_GQR5 & 0x3f000000) != 0) {
      ldexpf(-(bVar13 & 0x3f));
    }
    FUN_80006e34((int)((ulonglong)uVar55 >> 0x20),(float *)uVar55,param_3,param_4,param_5,param_6,
                 param_7,param_8,in_stack_ffffff0c,in_stack_ffffff10);
  }
  else {
    uVar23 = *(undefined4 *)(param_3 + 0x34);
    dVar44 = (double)*(float *)(param_3 + 4);
    puVar26 = &DAT_802c3d00;
    uVar55 = FUN_80007738((char)iVar21,(char)param_2,(char)param_3,(char)uVar23,(char)param_5,
                          (char)param_6,(char)param_7,(char)param_8,0,in_stack_ffffff10);
    bVar11 = (byte)unaff_GQR3 & 7;
    bVar16 = (byte)(unaff_GQR3 >> 8);
    if ((unaff_GQR3 & 0x3f00) == 0) {
      dVar42 = 1.0;
    }
    else {
      dVar42 = (double)ldexpf(bVar16 & 0x3f);
    }
    if (bVar11 == 4 || bVar11 == 6) {
      fVar56 = (float)CONCAT13((char)(dVar42 * dVar44),SUB43(in_stack_ffffff10,0));
    }
    else if (bVar11 == 5 || bVar11 == 7) {
      fVar56 = (float)CONCAT22((short)(dVar42 * dVar44),SUB42(in_stack_ffffff10,0));
    }
    else {
      fVar56 = (float)dVar44;
    }
    bVar12 = bVar12 & 7;
    if ((unaff_GQR3 & 0x3f000000) == 0) {
      lVar14 = 0x3ff0000000000000;
    }
    else {
      lVar14 = ldexpf(-(bVar15 & 0x3f));
    }
    if (bVar12 == 4 || bVar12 == 6) {
      dVar42 = (double)(lVar14 * (longlong)(double)(char)((uint)fVar56 >> 0x18));
    }
    else if (bVar12 == 5 || bVar12 == 7) {
      dVar42 = (double)(lVar14 * (longlong)(double)(short)((uint)fVar56 >> 0x10));
    }
    else {
      dVar42 = (double)fVar56;
    }
    fVar57 = *(float *)(unaff_r2 + -0x7ff4) * (float)(dVar44 - dVar42);
    bVar11 = (byte)unaff_GQR3 & 7;
    if ((unaff_GQR3 & 0x3f00) == 0) {
      dVar44 = 1.0;
    }
    else {
      dVar44 = (double)ldexpf(bVar16 & 0x3f);
    }
    if (bVar11 == 4 || bVar11 == 6) {
      fVar57 = (float)CONCAT13((char)(dVar44 * (double)fVar57),SUB43(fVar56,0));
    }
    else if (bVar11 == 5 || bVar11 == 7) {
      fVar57 = (float)CONCAT22((short)(dVar44 * (double)fVar57),SUB42(fVar56,0));
    }
    uVar25 = 4;
    uVar22 = FUN_80006e34((int)((ulonglong)uVar55 >> 0x20),(float *)uVar55,param_3,uVar23,param_5,
                          param_6,param_7,4,puVar26,fVar57);
    uVar23 = *(undefined4 *)(param_3 + 0x38);
    uVar55 = FUN_800074ec(uVar22,extraout_r4,(char)param_3,(char)uVar23,(char)param_5,(char)param_6,
                          (char)param_7,uVar25,(char)puVar26,fVar57);
    if ((unaff_GQR5 & 0x3f000000) != 0) {
      ldexpf(-(bVar13 & 0x3f));
    }
    FUN_80006e34((int)((ulonglong)uVar55 >> 0x20),(float *)uVar55,param_3,uVar23,param_5,param_6,
                 param_7,1,puVar26,fVar57);
  }
  return;
}

